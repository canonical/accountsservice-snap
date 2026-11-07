/*
 * chpasswd-guard: validating shim in front of the real chpasswd(8).
 *
 * The staged accounts-daemon execs its compiled-in "/usr/sbin/chpasswd -e"
 * and writes exactly one "username:crypt\n" record to the helper's stdin
 * without validating the caller-supplied crypt string for record separators
 * (SetPassword record injection: a crypt of "hash\notheruser:otherhash"
 * makes chpasswd change a second extrausers account in the same call).
 * The daemon binary cannot be patched, so the snap layout-binds this guard
 * over /usr/sbin/chpasswd in the daemon's mount namespace.
 *
 * Contract (the daemon's only use of chpasswd):
 *   argv:  <this program> -e
 *   stdin: exactly one "username:$6$salt$hash\n" record, newline-terminated.
 *
 * The guard reads stdin and validates the input against
 *   ^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,31}:\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+\n$
 * (single record, no CR/LF anywhere but the terminator, valid SHA-512 crypt
 * shape). On success it execs the REAL chpasswd ($SNAP/usr/sbin/chpasswd.real,
 * the byte-identical copy of the fat base's 1017 extrausers-fallback build)
 * with the original argv and re-feeds the unchanged input, propagating the
 * child's exit status. Anything else is rejected with a message on stderr and
 * exit 2; the daemon surfaces chpasswd failures to the D-Bus caller.
 * Rejection messages deliberately do not echo the input (crypt material).
 */

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* A single record is ~130 bytes; this cap only bounds a runaway writer. */
#define MAX_INPUT (1u << 20)

static int is_user_first(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_';
}

static int is_user_rest(char c)
{
    return is_user_first(c) || c == '-';
}

static int is_crypt(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '/';
}

static int reject(const char *reason)
{
    fprintf(stderr, "chpasswd-guard: rejected SetPassword input: %s\n", reason);
    return 2;
}

/* username [$6$ salt $ hash], per the regex in the header comment. */
static int valid_record(const char *line, size_t len)
{
    const char *colon = memchr(line, ':', len);
    if (colon == NULL)
        return 0;

    size_t ulen = (size_t)(colon - line);
    if (ulen < 1 || ulen > 32)
        return 0;
    if (!is_user_first(line[0]))
        return 0;
    for (size_t i = 1; i < ulen; i++)
        if (!is_user_rest(line[i]))
            return 0;

    const char *rest = colon + 1;
    size_t rlen = len - ulen - 1;
    if (rlen < 6)
        return 0;
    if (rest[0] != '$' || rest[1] != '6' || rest[2] != '$')
        return 0;

    size_t i = 3, salt = 0;
    while (i < rlen && is_crypt(rest[i])) {
        i++;
        salt++;
    }
    if (salt < 1 || i >= rlen || rest[i] != '$')
        return 0;

    for (i++; i < rlen; i++)
        if (!is_crypt(rest[i]))
            return 0;
    return 1; /* hash ran to the end of the line, non-empty */
}

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "-e") != 0)
        return reject("this wrapper only forwards `chpasswd -e` (crypt mode)");

    signal(SIGPIPE, SIG_IGN);

    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (buf == NULL)
        return reject("out of memory");

    for (;;) {
        if (len == cap) {
            if (cap >= MAX_INPUT)
                return reject("input too large");
            cap *= 2;
            char *nbuf = realloc(buf, cap);
            if (nbuf == NULL)
                return reject("out of memory");
            buf = nbuf;
        }
        ssize_t n = read(STDIN_FILENO, buf + len, cap - len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return reject("read error on stdin");
        }
        if (n == 0)
            break;
        len += (size_t)n;
    }

    if (len == 0)
        return reject("empty input");
    if (buf[len - 1] != '\n')
        return reject("unterminated record (input must end with a newline)");
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\r')
            return reject("CR in input");
    /* Exactly one record: a single '\n', and it is the terminator. Any other
     * newline inside the caller-supplied crypt would start a second chpasswd
     * record against another account (the injected-record attack). */
    size_t nl = 0;
    for (size_t i = 0; i + 1 < len; i++)
        if (buf[i] == '\n')
            nl++;
    if (nl != 0)
        return reject("multiple records (newline in the crypt string)");
    if (!valid_record(buf, len - 1))
        return reject("record does not match username:$6$salt$hash");

    const char *snap = getenv("SNAP");
    char real[4096];
    if (snap != NULL && *snap != '\0')
        snprintf(real, sizeof(real), "%s/usr/sbin/chpasswd.real", snap);
    else
        snprintf(real, sizeof(real),
                 "/snap/accountsservice/current/usr/sbin/chpasswd.real");

    int pfd[2];
    if (pipe(pfd) != 0)
        return reject("pipe failed");
    pid_t pid = fork();
    if (pid < 0)
        return reject("fork failed");
    if (pid == 0) {
        close(pfd[1]);
        if (dup2(pfd[0], STDIN_FILENO) != 0)
            _exit(127);
        close(pfd[0]);
        execv(real, argv);
        fprintf(stderr, "chpasswd-guard: exec %s: %s\n", real, strerror(errno));
        _exit(127);
    }

    close(pfd[0]);
    const char *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t w = write(pfd[1], p, left);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break; /* child died early; its exit status reports the failure */
        }
        p += w;
        left -= (size_t)w;
    }
    close(pfd[1]);

    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR)
            return reject("waitpid failed");
    }
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return 2;
}
