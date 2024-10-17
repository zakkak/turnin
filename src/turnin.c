/*******************************************************************************
 *
 * Copyright 1993      Paul Eggert
 * Copyright 1993      Dave Probert     <probert@cs.ucsb.edu>
 * Copyright 2000      Andy Pippin      <abp@cs.ucsb.edu>
 * Copyright 2000-2010 Jeff Sheltren    <sheltren@cs.ucsb.edu>
 * Copyright 2010-2014 Bryce Boe        <bboe@cs.ucsb.edu>
 * Copyright 2014      Foivos S. Zakkak <foivos@zakkak.net> and
 *                     Antonios Chariton<daknob.mac@gmail.com>
 * Copyright 2015-2022 Foivos S. Zakkak <foivos@zakkak.net>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *******************************************************************************
 *
 * Instructor creates subdirectory TURNIN in home directory of the class
 * account.  For each assignment, a further subdirectory must be created
 * bearing the name of the assignment (e.g.  ~class/TURNIN/as2).
 *
 * If there is a file 'LIMITS', it is examined for lines like:
 *
 * maxfiles 100
 * maxkbytes 1000
 * maxturnins 10
 * binary 0
 * daypenalty 10
 * weekendpenalty 5
 * duedate YYYYMMDD HH:MM
 * lockdate YYYYMMDD HH:MM
 *
 * which are used to modify the default values governing student turnins of
 * assignments (the default values are shown above).
 *
 * User files are saved in compressed tar images in the assignment
 * subdirectory.  The most recent version for each student is named
 *
 *    user.tgz
 *
 * previously turned versions are called user-N.tgz, where higher
 * N refer to more recent turnins.  At most MAXTURNINS can be made
 * for each assignment.
 *
 * If there is a file README in the turnin directory, it is printed when the
 * user runs turnin.
 *
 * The file LOGFILE is appended for each turnin.
 *
 * The file SHA256 is appended for each turnin.
 *
 * As far as the user is concerned, the syntax is simply:
 *
 *    turnin  assignment@class file1 [file2 [...]]
 *
 ******************************************************************************/

#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <openssl/sha.h>

#include <fcntl.h>

#include <glob.h>

#include "version.h"

#define MAX_PATH_LENGTH 4096

char        *user_name;
char        *assignment, *class;
unsigned int class_uid, user_uid, class_gid, user_gid;

int maxfiles       = 100;
int maxkbytes      = 1000;
int maxturnins     = 10;
int binary         = 0;
int daypenalty     = 10;
int weekendpenalty = 5;
int showpenalty    = 1;
int penalty = 0;

time_t duedate  = 0;
time_t lockdate = 0;

int nfiles, nkbytes, nsymlinks;

char *assignment_path, *assignment_file;
char *assignment_path_files[] = {"on_time", "late"};
int   saveturnin              = 1;
#define MAX_FILENAME_LENGTH 256

char *tarcmd;

typedef struct fdescr {
	char          *f_name;
	int            f_flag;
	time_t         f_mtime;
	size_t         f_size;
	char          *f_symlink;
	struct fdescr *f_link;
} Fdescr;

/*
 * f_flag values
 */
#define F_OK        0
#define F_NOTFILE   1
#define F_BINFILE   2
#define F_TMPFILE   3
#define F_HIDDEN    4
#define F_NOTOWNER  5
#define F_DOTDOT    6
#define F_ROOTED    7
#define F_NOEXIST   8
#define F_COREFILE  9
#define F_PERM      10
#define F_DIRECTORY 11
#define F_NOTDIR    12
#define F_SYMLINK   13

Fdescr *fileroot, *filenext;

/*
 * get arguments: assignment, class, list of files-and-directories
 */
void usage() {
	fprintf(stderr, "Usage: turnin [-h|--help] [-V|--version] assignment@class file1 [file2 [...]]\n");
	exit(1);
}

/*
 * get arguments: assignment, class, list of files-and-directories
 */
void version() {
	fprintf(stderr,
	        "turnin %s\n\n"
	        "Copyright 1993      Paul Eggert\n"
	        "Copyright 1993      Dave Probert     <probert@cs.ucsb.edu>\n"
	        "Copyright 2000      Andy Pippin      <abp@cs.ucsb.edu>\n"
	        "Copyright 2000-2010 Jeff Sheltren    <sheltren@cs.ucsb.edu>\n"
	        "Copyright 2010-2014 Bryce Boe        <bboe@cs.ucsb.edu>\n"
	        "Copyright 2014      Foivos S. Zakkak <foivos@zakkak.net> and\n"
	        "                    Antonios Chariton<daknob.mac@gmail.com>\n"
	        "Copyright 2015-2022 Foivos S. Zakkak <foivos@zakkak.net>\n"
			"Copyright 2024 	 Paul Walther     <paul.walther@tum.de>\n\n"
	        "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
	        "This is free software: you are free to change and redistribute it.\n"
	        "There is NO WARRANTY, to the extent permitted by law.\n\n"
	        "The source code is available at <https://github.com/zakkak/turnin>\n",
	        turninversion);
	exit(0);
}

/*
 * Checks path for malicious tricks, such as escaped backspaces etc.
 *
 * FIXME: Only supports a subset of ASCII at the moment
 */
void check_assignment(char *s) {
	if (*s == '/') {
		fprintf(stderr, "turnin: The assignment cannot be an absolute path.\n"
		                "        Please ask for help.\n");
		exit(1);
	}

	for (; *s; s++) {
		if (!((*s == ' ') || (*s == '_') || (*s == '-') || (*s == '/') || ((*s >= '0') && (*s <= '9')) ||
		      ((*s >= 'a') && (*s <= 'z')) || ((*s >= 'A') && (*s <= 'Z')))) {
			fprintf(stderr, "turnin: An assignment can include only ascii characters in [a-zA-Z0-9 /_-]\n");
			exit(1);
		}
	}
}

char *timestamp(time_t clock) {
	char      *b = (char *)malloc(16);
	struct tm  t;
	struct tm *res = localtime_r(&clock, &t);

	if (res != &t) {
		fprintf(stderr, "turnin: Cannot create timestamp\n"
		                "        Please report this issue to the system administrators\n");
		exit(1);
	}

	sprintf(b, "%02d/%02d/%02d %02d:%02d", t.tm_mon + 1, t.tm_mday, t.tm_year % 100, t.tm_hour, t.tm_min);
	return b;
}

void be_class() {
	if (seteuid(0) == -1) {
		perror("seteuid root");
		exit(1);
	}

	if (setegid(0) != 0) {
		perror("setegid root");
		exit(1);
	}

	if (setegid(class_gid) == -1) {
		perror("setegid class");
		exit(1);
	}

	if (seteuid(class_uid) == -1) {
		perror("seteuid class");
		exit(1);
	}
}

void be_user() {
	if (seteuid(0) == -1) {
		perror("seteuid root");
		exit(1);
	}
	if (setegid(0) == -1) {
		perror("setegid root");
		exit(1);
	}

	if (setegid(user_gid) == -1) {
		perror("setegid user");
		exit(1);
	}
	if (seteuid(user_uid) == -1) {
		perror("seteuid user");
		exit(1);
	}
}

void wanttocontinue() {
	int c, t;

	do {
		fprintf(stderr, "*** Do you want to continue? (y/n) ");

		c = getchar();

		switch (c) {
		case EOF:
			/* Abort on EOF to avoid infinite loops in case of dropped
			 * ssh sessions or redirected input from non properly
			 * formatted files */
			fprintf(stderr, "\n**** ABORTING TURNIN - Input reached EOF ****\n");
			exit(0);
		case '\n': continue; break;
		default: c = tolower(c); break;
		}

		/* Handle more than one characters, if more than one
		 * characters was given ask again */
		/* Get the rest of the input */
		while (((t = getchar()) != '\n') && (t != EOF)) {
			/* set c to something different than 'y' and 'n' */
			c = 0;
		}
		/* clear EOF in case it was reached */
		clearerr(stdin);

	} while (c != 'y' && c != 'n');

	if (c == 'n') {
		fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
		exit(0);
	}
	return;
}

/*
 * Find longest submissions path
 * Using for malloc
 */
int find_longest_sub_path() {
	unsigned int i;
	int          current, longest_path = 0;

	for (i = 0; i < sizeof(assignment_path_files) / sizeof(char *); i++) {
		current = strlen(assignment_path_files[i]);
		if (current > longest_path) {
			longest_path = current;
		}
	}

	return longest_path;
}

void check_submissions_paths() {
	char        *submissions_paths;
	int          longest_path = 0;
	int          path_len     = 0;
	unsigned int i;
	struct stat  stat;

	/* find longest submissions path */
	longest_path = find_longest_sub_path();

	/* assignment_path is in the class' home directory */
	/* plus longest_path submissions */
	/* plus 2 for begin '/' and end '/' */
	/* plus 2 is for adding the '/' and '\0' */

	path_len = strlen(assignment_path) + longest_path + 2 + 2;

	if (path_len > (MAX_PATH_LENGTH - MAX_FILENAME_LENGTH)) {
		fprintf(stderr, "turnin: turnin path for submissions longer than %d\n", MAX_PATH_LENGTH);
		exit(1);
	}

	for (i = 0; i < sizeof(assignment_path_files) / sizeof(char *); i++) {
		submissions_paths = (char *)malloc((path_len + MAX_FILENAME_LENGTH) * sizeof(char));
		strncpy(submissions_paths, assignment_path, strlen(assignment_path) - 1); // -1 for traling '.'
		submissions_paths[strlen(assignment_path) - 1] = '\0';
		strcat(submissions_paths, assignment_path_files[i]);

		/* Does it exist? */
		if (lstat(submissions_paths, &stat) == -1) {
			/* If not create them */
			if (mkdir(submissions_paths, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == -1) {
				fprintf(stderr,
				        "turnin: Failed to create directory %s.\n"
				        "        Please mention this to the instructor or the TAs.\n",
				        submissions_paths);
				perror(submissions_paths);
				exit(1);
			}
			if (lstat(submissions_paths, &stat) == -1) {
				/* Should never reach here */
				fprintf(stderr,
				        "turnin: Something is wrong with the new directory %s.\n"
				        "        Please mention this to the instructor or the TAs.\n",
				        submissions_paths);
				exit(1);
			}
		}

		/* Does class own this directory? */
		if (stat.st_uid != class_uid) {
			fprintf(stderr,
			        "turnin: %s not owned by %s.\n"
			        "        Please mention this to the instructor or the TAs.\n",
			        submissions_paths, class);
			exit(1);
		}

		/* Is it a directory ? */
		if ((stat.st_mode & S_IFMT) != S_IFDIR) {
			fprintf(stderr,
			        "turnin: %s not a directory.\n"
			        "        Please mention this to the instructor or the TAs.\n",
			        submissions_paths);
			exit(1);
		}

		/* Does the class have RWX permissions on the directory ?
		 * We need read to check for old turnins. Write to turnin the new one and
		 * Execute because it is a directory */
		if ((stat.st_mode & S_IRWXU) != S_IRWXU) {
			fprintf(stderr,
			        "turnin: %s has invalid permissions.\n"
			        "        Please mention to the instructor or the TAs\n",
			        submissions_paths);
			exit(1);
		}
		free(submissions_paths);
	}
}

/*
 * Check date format in LIMITS
 * Example:
 *   %Y%m%d %H:%M - 20150101 23:59
 */
int check_date(char *str_date, time_t *t) {
	struct tm tm = {0};

	/* check date length format 20150101 23:59 */
	if (strlen(str_date) != 14)
		return 0;

	if (strptime(str_date, "%Y%m%d %H:%M", &tm) == NULL)
		return 0;

	tm.tm_isdst = -1;
	*t          = mktime(&tm);
	if (*t == -1)
		return 0;

	return 1;
}

void setup(char *arg) {
	struct passwd *pwd;
	struct stat    stat;
	char           buf[256], *p;
	FILE          *fd;

	char keyword[256];
	char str_date[32];
	int  n;
	int  i, warn;

	time_t curr_time;
	double diff_time;

	glob_t glob_buffer = {0};
	int    file_exists;

	/* Check if it was compiled/setup properly */
	if (geteuid() != 0) {
		fprintf(stderr, "turnin: turnin must be compiled and installed as root.\n"
		                "        Please report this issue to the system administrators.\n");
		exit(1);
	}

	/* get the user's login */
	user_uid = getuid();

	pwd = getpwuid(user_uid);

	if (!pwd) {
		fprintf(stderr,
		        "turnin: Cannot lookup user (uid %d)\n"
		        "        Please report this issue to the system administrators\n",
		        user_uid);
		exit(1);
	}

	if (!pwd->pw_name) {
		fprintf(stderr,
		        "turnin: Cannot lookup user_name (uid %d)\n"
		        "        Please report this issue to the system administrators\n",
		        user_uid);
		exit(1);
	}
	user_name = strdup(pwd->pw_name);

	/* Search for @ in the first argument and split it there */
	assignment = arg;
	class      = strchr(assignment, '@');

	if (!class)
		usage();

	*class ++ = '\0';

	/* check assignment to make sure it is a valid path */
	check_assignment(assignment);

	pwd = getpwnam(class);
	if (!pwd) {
		fprintf(stderr, "turnin: '%s' is not a valid course\n", class);
		exit(1);
	}

	class_uid = pwd->pw_uid;
	class_gid = pwd->pw_gid;

	if (!class_uid) {
		fprintf(stderr, "turnin: Cannot turnin to root\n");
		exit(1);
	}

	/* assignment path is in the class' home directory */
	/* plus 2 is for adding the '/' and '\0' */
	i = strlen(pwd->pw_dir) + strlen("/TURNIN/") + strlen(assignment) + 2;

	if (i > (MAX_PATH_LENGTH - MAX_FILENAME_LENGTH)) {
		fprintf(stderr, "turnin: turnin path longer than %d\n", MAX_PATH_LENGTH);
		exit(1);
	}

	if (assignment[0] == '\0') {
		fprintf(stderr, "turnin: assignment name cannot be empty\n");
		exit(1);
	}

	assignment_path = (char *)malloc(i + MAX_FILENAME_LENGTH);
	strcpy(assignment_path, pwd->pw_dir);
	strcat(assignment_path, "/TURNIN/");
	strcat(assignment_path, assignment);
	strcat(assignment_path, "/");
	assignment_file = assignment_path + i - 1;

	/*
	 * Check on needed system commands
	 */
	if (access("/bin/tar", X_OK) == 0)
		tarcmd = "/bin/tar";
	else {
		fprintf(stderr, "turnin: Cannot find tar command\n"
		                "        Please mention this to the system administrators\n");
		exit(1);
	}

	assignment_file[0] = '.';
	assignment_file[1] = 0;

	/* checks for final (class) directory */
	be_class();

	/* Does it exist? */
	if (lstat(assignment_path, &stat) == -1) {
		perror(assignment_path);
		exit(1);
	}

	/* Does class own this directory? */
	if (stat.st_uid != class_uid) {
		fprintf(stderr,
		        "turnin: %s not owned by %s.\n"
		        "        Please mention this to the instructor or the TAs.\n",
		        assignment_path, class);
		exit(1);
	}

	/* Is it a directory ? */
	if ((stat.st_mode & S_IFMT) != S_IFDIR) {
		fprintf(stderr,
		        "turnin: %s not a directory.\n"
		        "        Please mention this to the instructor or the TAs.\n",
		        assignment_path);
		exit(1);
	}

	/* Does the class have RWX permissions on the directory ?
	 * We need read to check for old turnins. Write to turnin the new one and
	 * Execute because it is a directory */
	if ((stat.st_mode & S_IRWXU) != S_IRWXU) {
		fprintf(stderr,
		        "turnin: %s has invalid permissions.\n"
		        "        Please mention this to the instructor or the TAs\n",
		        assignment_path);
		exit(1);
	}

	check_submissions_paths();

	/*
	 * Check limits file
	 */
	strcpy(assignment_file, "LIMITS");
	fd = fopen(assignment_path, "r");
	if (fd) {
		while (fgets(buf, sizeof(buf) - 1, fd) == buf) {
			/* Ignore comments */
			if ((p = strchr(buf, '#')))
				*p-- = 0;
			else
				p = buf + strlen(buf) - 1;

			while (p >= buf && isspace(*p))
				--p;

			if (p == buf - 1)
				continue;

			p[1] = 0; /* Remove trailing spaces */

			/* Remove spaces from the start */
			for (p = buf; *p && isspace(*p); p++)
				;

			memset((void *)str_date, 0, sizeof(str_date));

			warn = 0;
			if (sscanf(buf, "%s %d", keyword, &n) != 2) {
				warn = 1;
			} else if (strcasecmp(keyword, "maxfiles") == 0) {
				if (n < 1) {
					fprintf(stderr, "turnin: maxfiles in the LIMITS file must be a non-zero positive value\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
				maxfiles = n;
			} else if (strcasecmp(keyword, "maxkbytes") == 0) {
				if (n < 1) {
					fprintf(stderr, "turnin: maxkbytes in the LIMITS file must be a non-zero positive value\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
				maxkbytes = n;
			} else if (strcasecmp(keyword, "maxturnins") == 0) {
				if (n < 1) {
					fprintf(stderr, "turnin: maxturnins in the LIMITS file must be a non-zero positive value\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
				maxturnins = n;
			} else if (strcasecmp(keyword, "binary") == 0) {
				if ((n != 0) && (n != 1)) {
					fprintf(stderr, "turnin: binary in the LIMITS file can only be 1 or 0\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
				binary = n;
			} else if (strcasecmp(keyword, "daypenalty") == 0) {
				if (n < 0 || n > 100) {
					fprintf(stderr, "turnin: daypenalty in the LIMITS file must be a positive value - (0 < penalty < 100)\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
				daypenalty = n;
			} else if (strcasecmp(keyword, "weekendpenalty") == 0) {
				if (n < 0 || n > 100) {
					fprintf(stderr, "turnin: weekendpenalty in the LIMITS file must be a positive value - (0 < penalty < 100)\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
				weekendpenalty = n;
			} else if (strcasecmp(keyword, "showpenalty") == 0) {
				if ((n != 0) || (n != 1)) {
					fprintf(stderr, "turnin: showpenalty must be either 0 or 1\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
				showpenalty = n;
			} 
			else if (strcasecmp(keyword, "duedate") == 0) {
				if (sscanf(buf, "%s %14c", keyword, str_date) != 2) {
					warn = 1;
				} else if (!check_date(str_date, &duedate)) {
					fprintf(stderr, "turnin: duedate in the LIMITS file must be a YYYYMMDD HH:MM format\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
			} else if (strcasecmp(keyword, "lockdate") == 0) {
				if (sscanf(buf, "%s %14c", keyword, str_date) != 2) {
					warn = 1;
				} else if (!check_date(str_date, &lockdate)) {
					fprintf(stderr, "turnin: lockdate in the LIMITS file must be a YYYYMMDD HH:MM format\n"
					                "        Please notify the Instructor or a TA.\n");
					exit(1);
				}
			} else {
				warn = 1;
			}
			if (warn) {
				fprintf(stderr, "turnin: Could not parse LIMITS file\n"
				                "        This is harmless, but please mention to instructor\n");
			}
		}
		(void)fclose(fd);
	}

	/* Check if the assignment is locked */
	curr_time = time(0);
	if (lockdate != 0) {
		diff_time = difftime(curr_time, lockdate);
		if (diff_time > 0) {
			*assignment_file = '\0';
			fprintf(stderr,
			        "turnin: Assignment directory locked: %s.\n"
			        "        Please contact the instructor or a TA\n",
			        assignment_path);
			exit(1);
		}
	}

	/*
	 * If there is a README file print it out.
	 * (someday use a pager)
	 */
	strcpy(assignment_file, "README");
	fd = fopen(assignment_path, "r");
	if (fd) {
		int c;
		fprintf(stderr, "*************** README **************\n");
		for (c = fgetc(fd); c != EOF; c = fgetc(fd)) {
			putchar(c);
		}
		fprintf(stderr, "*************************************\n");
		(void)fclose(fd);
		wanttocontinue();
	}

	/*
	 * Check for multiple turnins
	 */
	strcpy(assignment_file, user_name);
	strcat(assignment_file, ".tgz");

	if (lstat(assignment_path, &stat) != -1) {
		/* compute next version name */
		for (saveturnin = 1; saveturnin <= maxturnins; saveturnin++) {
			file_exists = 1;

			sprintf(assignment_file, "{on_time,late}/%s-%d{,-*}.tgz", user_name, saveturnin);
			glob(assignment_path, GLOB_BRACE, NULL, &glob_buffer);
			if (glob_buffer.gl_pathc == 0)
				file_exists = 0;
			globfree(&glob_buffer);

			if (!file_exists)
				break;
		}

		if (saveturnin > maxturnins) {
			fprintf(stderr, "\n*** MAX (%d) TURNINS REACHED FOR %s ***\n", maxturnins, assignment);
			fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
			exit(1);
		} else {
			fprintf(stderr,
			        "\n"
			        "*** You have already turned in %s ***\n"
			        "    You have %d more turnins!\n",
			        assignment, maxturnins - saveturnin + 1);
		}

		wanttocontinue();
	}

	be_user();
}

int isbinaryfile(char *s) {
	char  buf[256];
	char *p;
	int   n, f, c;

	f = open(s, 0);
	if (f == -1) {
		perror(s);
		exit(1);
	}

	n = read(f, buf, sizeof(buf));
	if (n == -1) {
		perror(s);
		exit(1);
	}
	(void)close(f);

	p = buf;
	while (n-- > 0) {
		c = *p++ & 0xff;
		if (c == 0)
			return 1;
		/* The following works only for ascii. Not valid for
		 * unicode */
		/* if (c & 0x80) return 1; */
	}

	return 0;
}

void addfile(char *s) {
	struct stat    stat;
	struct dirent *dp;
	DIR           *dirp;
	Fdescr        *f;
	char           b[MAX_PATH_LENGTH];
	char          *p, *t;
	int            sl, i;
	int            must_be_dir;
	char          *tmp;

	/* FIXME: these are never freed */
	f = (Fdescr *)malloc(sizeof(Fdescr));
	memset((void *)f, 0, sizeof(Fdescr));

	sl = strlen(s);

	if (!fileroot) {
		fileroot = filenext = f;
	} else {
		filenext->f_link = f;
		filenext         = f;
	}

	must_be_dir = 0;
	/* Eat trailing slashes from directories */
	while (sl > 1 && s[sl - 1] == '/') {
		s[sl - 1] = 0;
		sl--;
		must_be_dir = 1;
	}

	f->f_name = strdup(s);

	/* Ignore core dumps */
	if (strcmp(s, "core") == 0) {
		f->f_flag = F_COREFILE;
		return;
	}

	/* Ignore hidden files or directories */
	tmp = strrchr(s, '/');
	if (tmp && (strchr(tmp, '.') == (tmp + 1))) {
		f->f_flag = F_HIDDEN;
		return;
	}

	/* Check if it exists to prevent tar from crashing */
	if (lstat(s, &stat) == -1) {
		f->f_flag = F_NOEXIST;
		return;
	}

	/* sanity check, if it ends with a / it must be a directory */
	if (must_be_dir && (stat.st_mode & S_IFMT) != S_IFDIR) {
		f->f_flag = F_NOTDIR;
		return;
	}

	/* If it is a regular file (i.e. not a symlink or dir) */
	if ((stat.st_mode & S_IFMT) == S_IFREG) {
		if ((stat.st_mode & S_IRUSR) != S_IRUSR)
			f->f_flag = F_PERM;
		else if (isbinaryfile(s))
			if (binary) {
				f->f_flag  = F_OK;
				f->f_mtime = stat.st_mtime;
				f->f_size  = stat.st_size;
			} else
				f->f_flag = F_BINFILE;
		else {
			f->f_mtime = stat.st_mtime;
			f->f_size  = stat.st_size;
			f->f_flag  = F_OK;
		}
		return;
	}

	/* If is is a symlink get its target for printing purposes only */
	if ((stat.st_mode & S_IFMT) == S_IFLNK) {

		/* zero out the bufer */
		memset((void *)b, 0, sizeof(b));

		/* get the link target in b */
		if (readlink(s, b, sizeof(b)) == -1) {
			perror(s);
			exit(1);
		}

		f->f_flag    = F_SYMLINK;
		f->f_symlink = strdup(b);
		return;
	}

	/* if it is not a regular file nor a symlink nor a directory */
	if ((stat.st_mode & S_IFMT) != S_IFDIR) {
		f->f_flag = F_NOTFILE;
		return;
	}

	f->f_flag = F_DIRECTORY;

	dirp = opendir(s);
	if (!dirp) {
		f->f_flag = F_NOTDIR;
		return;
	}

	while ((dp = readdir(dirp)) != NULL) {
		p = dp->d_name;
		/* Ignore . and .. */
		if (!(strcmp(p, ".") == 0) && !(strcmp(p, "..") == 0)) {
			i = sl + 1 + strlen(p) + 1;
			t = (char *)malloc(i);
			strcpy(t, s);
			strcat(t, "/");
			strcat(t, p);
			addfile(t);
			free(t);
		}
	}

	(void)closedir(dirp);
}

/*
 * List all filenames that are to be excluded.
 * Return the number of files excluded.
 */
int warn_excludedfiles() {
	Fdescr *fp;
	char   *msg   = 0;
	int     first = 1;

	for (fp = fileroot; fp; fp = fp->f_link) {
		switch (fp->f_flag) {
		case F_NOTFILE: msg = "not a file, directory, or symlink"; break;
		case F_BINFILE: msg = "binary file"; break;
		case F_TMPFILE: msg = "temporary file"; break;
		case F_HIDDEN: msg = "hidden file or directory"; break;
		case F_NOTOWNER: msg = "not owned by user"; break;
		case F_DOTDOT: msg = "pathname contained '..'"; break;
		case F_ROOTED: msg = "only relative pathnames allowed"; break;
		case F_NOEXIST: msg = "does not exist"; break;
		case F_COREFILE: msg = "may not turnin core files"; break;
		case F_PERM: msg = "no access permissions"; break;
		case F_NOTDIR: msg = "error reading directory"; break;
		case F_DIRECTORY: msg = 0; break;
		case F_SYMLINK: msg = 0; break;
		case F_OK: msg = 0; break;
		default: fprintf(stderr, "turnin: INTERNAL ERROR: %d f_flag UNKNOWN\n", fp->f_flag);
		}
		if (msg) {
			if (first) {
				first = 0;
				fprintf(stderr, "\n************** WARNINGS **************\n");
			}
			fprintf(stderr, "%s: NOT TURNED IN: %s\n", fp->f_name, msg);
		}
	}
	return !first;
}

/*
 * Tally up the summary info
 * Return TRUE if limits exceeded or no available space.
 */
int computesummaryinfo() {
	Fdescr *fp;
	int     fatal = 0;

	for (fp = fileroot; fp; fp = fp->f_link) {
		if (fp->f_flag == F_SYMLINK)
			nsymlinks++;
		else if (fp->f_flag == F_OK) {
			nfiles++;
			nkbytes = nkbytes + (fp->f_size + 1023) / 1024;
		}
	}

	if (nfiles > maxfiles) {
		fprintf(stderr,
		        "turnin: A maximum of %d files may be turned in for this assignment.\n"
		        "        You are attempting to turn in %d files.\n",
		        maxfiles, nfiles);
		fatal++;
	}

	if (nkbytes > maxkbytes) {
		fprintf(stderr,
		        "turnin: A maximum of %d Kbytes may be turned in for this assignment.\n"
		        "        You are attempting to turn in %d Kbytes.\n",
		        maxkbytes, nkbytes);
		fatal++;
	}

	return fatal;
}

/*
 * For each file that will actually be turned in, print the
 * filename and modification date.  Make special notations for
 * symbolic links.
 */
void printverifylist() {
	Fdescr *f;
	int     n = 0;
	char   *msg[2];
	char   *time;

	fprintf(stderr, "\n*** These are the regular files being turned in:\n\n");
	fprintf(stderr, "\t    Last Modified   Size   Filename\n");
	fprintf(stderr, "\t    -------------- ------  -------------------------\n");

	for (f = fileroot; f; f = f->f_link) {
		if (f->f_flag != F_OK)
			continue;
		n++;
		time = timestamp(f->f_mtime);
		fprintf(stderr, "\t%2d: %s %6u  %s\n", n, time, (unsigned int)f->f_size, f->f_name);
		free(time);
	}

	msg[0] = "\nThese are the symbolic links being turned in:\n";
	msg[1] = "(Be sure the files referenced are turned in too)\n";

	for (f = fileroot; f; f = f->f_link) {
		if (f->f_flag != F_SYMLINK)
			continue;
		if (msg[0])
			fprintf(stderr, "%s%s", msg[0], msg[1]);
		msg[0] = 0;
		n++;
		fprintf(stderr, "\t%2d: %s -> %s\n", n, f->f_name, f->f_symlink);
	}
}

/*
 * make the tar image in a temporary file in the assignment directory.
 *
 * su:user tar czf - file-list | su:class tee tempfile > /dev/null in assignmentdir
 */
char *tempfile;

/*
 * Creates the archive and a link to it.
 */
void maketar() {
	int         ofd;
	int         childpid, childstat;
	int         tarpid, tarstat;
	int         failed;
	struct stat stat;

	char **targvp, **tvp;
	int    nleft;
	char  *target;

	Fdescr *fp;

	/*
	 * build the tar argument list
	 */
	tvp = targvp = (char **)malloc((5 + nfiles + nsymlinks + 1) * sizeof(char *));
	tvp[0]       = "tar";
	tvp[1]       = "czf";
	tvp[2]       = "-";
	tvp[3]       = "--exclude-backups";
	tvp[4]       = "--exclude-vcs";
	tvp += 5;

	nleft = nfiles + nsymlinks;

	for (fp = fileroot; fp; fp = fp->f_link) {
		if (fp->f_flag != F_OK && fp->f_flag != F_SYMLINK)
			continue;
		if (nleft-- < 0) {
			fprintf(stderr, "FATAL ERROR at LINE %d\n", __LINE__);
			exit(1);
		}
		*tvp++ = fp->f_name;
	}
	*tvp = 0;

	/*
	 * setup the target name
	 */
	if (penalty) {
		sprintf(assignment_file, "late/%s-%d-%d.tgz", user_name, saveturnin, penalty);
	} else {
		sprintf(assignment_file, "on_time/%s-%d.tgz", user_name, saveturnin);
	}

	be_class();

	/* The file should STILL not exist */
	if (lstat(assignment_path, &stat) != -1) {
		fprintf(stderr, "The final file '%s' already exists\n", assignment_path);
		fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
		exit(1);
	}

	ofd = open(assignment_path, O_CREAT | O_EXCL | O_WRONLY, 0600);

	if (ofd == -1) {
		perror(assignment_path);
		fprintf(stderr, "Could not open the final file: %s\n", assignment_path);
		fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
		if (lstat(assignment_path, &stat) != -1) {
			unlink(assignment_path);
		}
		exit(1);
	}

	be_user();

	/*
	 * Do the actual tar
	 */
	failed   = 0;
	childpid = fork();

	if (!childpid) { /* in child */

		tarpid = fork();
		if (!tarpid) {
			if (ofd != 1) {
				dup2(ofd, 1);
				(void)close(ofd);
			}
			execv(tarcmd, targvp);
			perror("tarcmd");
			_exit(1);
		}

		wait(&tarstat);
		if (tarstat)
			failed = -1;
		_exit(failed);
	}
	wait(&childstat);

	free(targvp);

	if (childstat) {
		fprintf(stderr,
		        "turnin: Subprocesses returned FAILED status: %x\n"
		        "        Contact the instructor or the TA\n",
		        childstat);
		(void)close(ofd);
		if (lstat(assignment_path, &stat) != -1) {
			unlink(assignment_path);
		}
		exit(1);
	}

	(void)close(ofd);

	/* Create a symlink to the latest version */
	/* 3 for penalty */
	/* 8 for submission folder */
	/* 9 for the letters and the '\0' + max possible digits of saveturnin */
	target = malloc((3 + 8 + 9 + 10 + strlen(user_name)) * sizeof(char));
	if (penalty) {
		sprintf(target, "./late/%s-%d-%d.tgz", user_name, saveturnin, penalty);
	} else {
		sprintf(target, "./on_time/%s-%d.tgz", user_name, saveturnin);
	}

	sprintf(assignment_file, "%s.tgz", user_name);

	be_class();

	if (symlink(target, assignment_path) != 0) {
		if (errno == EEXIST) { /* If the link already exists remove it */
			/* Check if it "really" exists */
			if (lstat(assignment_path, &stat) == -1) {
				fprintf(stderr, "turnin: Error while checking Symlink to latest turnin!\n"
				                "        Please notify the Instructor or a TA.\n");
				exit(1);
			} else if ((stat.st_mode & S_IFMT) != S_IFLNK) {
				/* If it is not a symlink report an error */
				fprintf(stderr, "turnin: Error with the symlink to the latest turnin!\n"
				                "        Please notify the Instructor or a TA.\n");
				exit(1);
			} else if (unlink(assignment_path) != 0) {
				fprintf(stderr, "turnin: Failed to delete symlink to latest turnin\n"
				                "        Please notify the Instructor or a TA.\n");
				perror("unlink");
				exit(1);
				/* after deletion retry */
			} else if (symlink(target, assignment_path) != 0) {
				fprintf(stderr, "turnin: Failed to create symlink to latest turnin.\n"
				                "        Please notify the Instructor or a TA.\n");
				perror("symlink");
				exit(1);
			}
		} else {
			fprintf(stderr, "turnin: Failed to create symlink to latest turnin.\n"
			                "        Please notify the Instructor or a TA.\n");
			perror("symlink");
			exit(1);
		}
	}

	be_user();

	free(target);
}

/*
 * Convert the sha digest to a string
 */
char *sha2string(unsigned char sha[SHA256_DIGEST_LENGTH]) {
	static char string[65]; /* Effectively global */
	int         i = 0;

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(string + (i * 2), "%02x", sha[i]);
	}

	string[64] = '\0';

	return string;
}

/*
 * Calculate the sha hash of the given file
 */
char *calculate_sha(char *filename) {
	unsigned char  sha[SHA256_DIGEST_LENGTH];
	FILE          *fd;
	SHA256_CTX     sha256;
	unsigned char *buf[1024];
	int            rbytes;

	fd = fopen(filename, "rb");
	if (!fd) {
		fprintf(stderr,
		        "turnin: Failed to open turned in file '%s' for sha-digest.\n"
		        "        Please notify the Instructor or a TA.\n",
		        filename);
		exit(1);
	}

	SHA256_Init(&sha256);

	while ((rbytes = fread(buf, 1, 1024, fd))) {
		SHA256_Update(&sha256, buf, rbytes);
	}

	SHA256_Final(sha, &sha256);

	fclose(fd);

	return sha2string(sha);
}

/*
 * Return string for log file
 */
char *getfilelog() {
	char *log;
	char *t;
	int   logl;

	t = timestamp(time(0));

	/* 14 for the format string
	 * 8 for the username
	 * 3 for the number of turnins
	 * 3 for the number of files
	 * 1 for '\0'
	 */
	logl = 14 + strlen(turninversion) + 8 + 3 + strlen(t) + 3 + 1;
	log  = malloc(logl * sizeof(char));
	snprintf(log, logl, "turnin %s: %-8s-%3d %s %3d\n", turninversion, user_name, saveturnin, t, nfiles + nsymlinks);

	free(t);

	return log;
}

/*
 * write the log entry
 *
 *  whichturnin, user, turnin number, date, time, number-of-files
 *
 */
void writelog() {
	char *log;
	char  sha[97]; /* 10 for the format string
	                * 64 for the sha256
	                * 8 for the username
	                * 10 for the number of turnins
	                * 3 for the penalty
	                * 1 for '\0'
	                * +1 to make it even
	                */
	int fd, x;

	log = getfilelog();

	be_class(); /* Be class before calculating the hash */

	if (penalty) {
		sprintf(assignment_file, "late/%s-%d-%d.tgz", user_name, saveturnin, penalty);
		snprintf(sha, 97, "%64s %8s-%d-%d.tgz\n", calculate_sha(assignment_path), user_name, saveturnin, penalty);

	} else {
		sprintf(assignment_file, "on_time/%s-%d.tgz", user_name, saveturnin);
		snprintf(sha, 94, "%64s %8s-%d.tgz\n", calculate_sha(assignment_path), user_name, saveturnin);
	}
	strcpy(assignment_file, "LOGFILE");

	fd = open(assignment_path, O_CREAT | O_WRONLY | O_APPEND | O_SYNC, 0600);
	if (fd == -1) {
		perror(assignment_path);
		fprintf(stderr, "turnin Warning: Could not open assignment log file\n");
	} else {
		x = fsync(fd);
		if (x == -1)
			perror("fsync");

		if (write(fd, log, strlen(log)) == -1) {
			fprintf(stderr, "turnin: Failed to write log");
			exit(1);
		}

		x = fsync(fd);
		if (x == -1)
			perror("fsync");
		(void)close(fd);
	}

	strcpy(assignment_file, "SHA256");

	fd = open(assignment_path, O_CREAT | O_WRONLY | O_APPEND | O_SYNC, 0600);
	if (fd == -1) {
		perror(assignment_path);
		fprintf(stderr, "turnin Warning: Could not open assignment sha256 file\n");
	} else {
		x = fsync(fd);
		if (x == -1)
			perror("fsync");

		if (write(fd, sha, strlen(sha)) == -1) {
			fprintf(stderr, "turnin: Failed to write sha256");
			exit(1);
		}

		x = fsync(fd);
		if (x == -1)
			perror("fsync");
		(void)close(fd);
	}

	be_user();

	free(log);
}

void checkdue() {
	FILE      *fd;
	struct tm  tm_curr;
	struct tm *res;
	time_t     curr_time;
	double     diff_time;
	int        diff_days;

	curr_time = time(0);

	/* Check if the assignment is due */
	if (duedate == 0)
		return;
	diff_time = difftime(curr_time, duedate);
	if (diff_time < 0)
		return;
	// calculate different days
	diff_days = (int)diff_time / 86400; // in days

	// calculate penalty
	res = localtime_r(&curr_time, &tm_curr);
	if (res != &tm_curr) {
		fprintf(stderr, "turnin: Cannot create timestamp to calculate initial penalty\n"
		                "        Please report this issue to the system administrators\n");
		exit(1);
	}
	penalty += (tm_curr.tm_wday == 0 || tm_curr.tm_wday == 6) ? weekendpenalty : daypenalty;

	for (; diff_days > 0; diff_days--) {
		curr_time -= 86400; // one day ago
		res = localtime_r(&curr_time, &tm_curr);
		if (res != &tm_curr) {
			fprintf(stderr, "turnin: Cannot create timestamp to calculate additional penalty\n"
			                "        Please report this issue to the system administrators\n");
			exit(1);
		}

		penalty += (tm_curr.tm_wday == 0 || tm_curr.tm_wday == 6) ? weekendpenalty : daypenalty;

		if (penalty >= 100) {
			fprintf(stderr, "\n*** The penalty, due to late turn in, is over 100%% ***\n");
			fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
			exit(1);
		}
	}
	/*
	 * If there is a LATEMESSAGE file print it out.
	 * (someday use a pager)
	 */
	strcpy(assignment_file, "LATEMESSAGE");
	fd = fopen(assignment_path, "r");
	if (fd) {
		int c;
		fprintf(stderr, "*************** LATEMESSAGE **************\n");
		for (c = fgetc(fd); c != EOF; c = fgetc(fd)) {
			putchar(c);
		}
		fprintf(stderr, "******************************************\n");
		(void)fclose(fd);
	}
	if ((penalty > 0)&& (showpenalty)) {
		fprintf(stderr, "\n*** This turn in will get %d%% penalty, due to late turn in, on the final grade ***\n", penalty);
	}
	wanttocontinue();
}

void ignore_signal(int signum) {
	struct sigaction previous_action;

	if (sigaction(signum, NULL, &previous_action) == -1) {
		perror("turnin: Failed to get previous sigaction");
	} else if (previous_action.sa_handler == SIG_DFL) {
		previous_action.sa_handler = SIG_IGN;
		if (sigaction(signum, &previous_action, NULL) == -1) {
			perror("turnin: Failed to set sigaction");
		}
	}
}

int main(int argc, char *argv[]) {

	if (argc > 1) {
		if (strstr(argv[1], "-h") || strstr(argv[1], "--help"))
			usage();

		if (strstr(argv[1], "-V") || strstr(argv[1], "--version"))
			version();

		if (argc < 3)
			usage();
	} else
		usage();

	/* Disable signals BEFORE we become class or root or whatever... */
	ignore_signal(SIGINT);
	ignore_signal(SIGTSTP);
	ignore_signal(SIGQUIT);
	ignore_signal(SIGHUP);
	ignore_signal(SIGTTIN);
	ignore_signal(SIGTTOU);

	/* initialize tzname before creating timestamps */
	tzset();
	setup(argv[1]);

	checkdue();

	argv += 2;
	argc -= 2;
	while (argc--)
		addfile(*argv++);

	if (warn_excludedfiles())
		wanttocontinue();

	if (computesummaryinfo()) {
		fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
		exit(1);
	}

	printverifylist();

	fprintf(stderr, "\n*************************************");
	fprintf(stderr, "***************************************\n\n");
	if (nsymlinks) {
		fprintf(stderr, "%s %d+%d (files+symlinks) [%dKB] for %s to %s\n", "You are about to turnin", nfiles, nsymlinks,
		        nkbytes, assignment, class);
	} else if (nfiles) {
		fprintf(stderr, "%s %d files [%dKB] for %s to %s\n", "You are about to turnin", nfiles, nkbytes, assignment, class);
	} else { /* if there are no files to turnin */
		fprintf(stderr, "%s %d files [%dKB] for %s to %s\n", "You are about to turnin", nfiles, nkbytes, assignment, class);
		fprintf(stderr, "turnin is aborting this submission as it is empty\n");
		exit(1);
	}

	wanttocontinue();

	maketar();

	writelog();

	/* Free memory */
	free(assignment_path);

	fprintf(stderr, "\n*** TURNIN OF %s TO %s COMPLETE! ***\n", assignment, class);
	exit(0);
}
