/*
 * This code is mainly taken from Doug Potter's page
 *
 * http://www-theorie.physik.unizh.ch/~dpotter/howto/daemonize
 *
 * I contacted him 2007-04-16 about the license for the original code,
 * he replied it is Public Domain.  Use the URL above to get the original
 * Public Domain version if you want it.
 *
 * This version is LGPL2 and is (c)2006 - 2013 Andy Green <andy@warmcat.com>
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

static int pid_daemon;
static char lock_path[PATH_MAX];

static void child_handler(int signum)
{
	int fd;
	char sz[20];

	switch (signum) {

	case SIGALRM: /* timedout daemonizing */
		exit(1);
		break;

	case SIGUSR1: /* positive confirmation we daemonized well */
		/* Create the lock file as the current user */

		fd = open(lock_path, O_TRUNC | O_RDWR | O_CREAT, 0640);
		if (fd < 0) {
			fprintf(stderr, "unable to create lock"
				" file %s, code=%d (%s)",
				lock_path, errno, strerror(errno));
			exit(1);
		}
		sprintf(sz, "%u", pid_daemon);
		write(fd, sz, strlen(sz));
		close(fd);
		exit(0);

	case SIGCHLD: /* daemonization failed */
		exit(1);
		break;
	}
}

/*
 * You just need to call this from your main(), when it
 * returns you are all set "in the background" decoupled
 * from the console you were started from.
 *
 * The process context you called from has been terminated then.
 */

int lws_daemonize(const char *_lock_path)
{
	pid_t sid, parent;

	/* already a daemon */
	if (getppid() == 1)
		return (1);

	strncpy(lock_path, _lock_path, sizeof lock_path);
	lock_path[sizeof(lock_path) - 1] = '\0';

	/* Trap signals that we expect to recieve */
	signal(SIGCHLD, child_handler);	/* died */
	signal(SIGUSR1, child_handler); /* was happy */
	signal(SIGALRM, child_handler); /* timeout daemonizing */

	/* Fork off the parent process */
	pid_daemon = fork();
	if (pid_daemon < 0) {
		fprintf(stderr, "unable to fork daemon, code=%d (%s)",
		    errno, strerror(errno));
		exit(1);
	}

	/* If we got a good PID, then we can exit the parent process. */
	if (pid_daemon > 0) {

		/*
		 * Wait for confirmation signal from the child via
		 * SIGCHILD / USR1, or for two seconds to elapse
		 * (SIGALRM).  pause() should not return.
		 */
		alarm(2);

		pause();
		/* should not be reachable */
		exit(1);
	}

	/* At this point we are executing as the child process */
	parent = getppid();

	/* Cancel certain signals */
	signal(SIGCHLD, SIG_DFL); /* A child process dies */
	signal(SIGTSTP, SIG_IGN); /* Various TTY signals */
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGHUP, SIG_IGN); /* Ignore hangup signal */

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		fprintf(stderr,
			"unable to create a new session, code %d (%s)",
			errno, strerror(errno));
		exit(1);
	}

	/*
	 * Change the current working directory.  This prevents the current
	 * directory from being locked; hence not being able to remove it.
	 */
	if ((chdir("/")) < 0) {
		fprintf(stderr,
			"unable to change directory to %s, code %d (%s)",
			"/", errno, strerror(errno));
		exit(1);
	}

	/* Redirect standard files to /dev/null */
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);

	/* Tell the parent process that we are A-okay */
	kill(parent, SIGUSR1);

	/* return to continue what is now "the daemon" */

	return (0);
}

