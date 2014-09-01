/*
 * 1993 version of the turnin program originally written by Paul Eggert
 *
 * Rewritten October 1993 by probert@cs.ucsb.edu
 *
 * Fixed Y2K bug in logging.  Andy Pippin <abp.cs.ucsb.edu>
 *
 * version 1.3: fix sprintf buffer overflow in writelog() - Jeff Sheltren <sheltren@cs.ucsb.edu>
 * Security flaw found by Stefan Karpinski <sgk@cs.ucsb.edu>
 *
 * v1.4: change functionality to work with newer NFS versions - Jeff Sheltren <sheltren@cs.ucsb.edu>
 * Now, it works something like this:
 * su user tar cf - assignment | su class gzip > /tmp/file; mv /tmp/file ~class/TURNIN/assignment
 *
 * 2010-11-04  Bryce Boe <bboe@cs.ucsb.edu>
 *    - Fixed ".." and "." in project name bug.
 *    - Also added exit(1) for user aborted exits.
 *
 * 2013-02-15  Bryce Boe <bboe@cs.ucsb.edu>
 *    - Check for EOF on input prompts to fix 100% CPU zombie processes bug
 *    - Reuse `wanttocontinue` for "already submitted prompt"
 *
 * 2014-09-01 Foivos S. Zakkak <foivos@zakkak.net>
 *    - Recursively check symlinks to get to the actual file
 *    - Reduced use of strcpy
 *    - Reduced attack surface
 *    - Ignore signals at the beginning (can't get interrupted while privileged)
 *    - Files renamed to *.tgz not *.tar.Z anymore
 *    - Some comments
 *    - isbinaryfile only checks for 0 since 0x80 results in false positives in
 *      unicode
 *    - Removed EQS define
 *    - Rename shufflenames to movetar
 *    - Add return type in functions
 *    - Remove unused variables
 *    - Fix Makefile
 *
 * Instructor creates subdirectory TURNIN in home directory of the class
 * account.  For each assignment, a further subdirectory must be created
 * bearing the name of the assignment (e.g.  ~cs162/TURNIN/pgm2).
 *
 * If the assignment directory contains the file 'LOCK' turnins will
 * not be accepted.
 *
 * If there is a file 'LIMITS', it is examined for lines like:
 *
 *		maxfiles	100
 *		maxkbytes	1000
 *		maxturnins	10
 *		binary		1
 *
 * which are used to modify the default values governing student turnins
 * of assignments (the default values are shown above).
 *
 * User files are saved in compressed tar images in the assignment
 * subdirectory.  The most recent version for each student is named
 *
 *		user.tgz
 *
 * previously turned versions are called user-N.tgz, where higher
 * N refer to more recent turnins.  At most MAXTURNINS can be made
 * for each assignment.
 *
 * If there is a file README in the turnin directory, it is printed
 * when the user runs turnin.
 *
 * The file LOGFILE is appended for each turnin.
 *
 * As far as the user is concerned, the syntax is simply:
 *
 *		turnin  assignmt@class   files-and-directories
 */

#define _XOPEN_SOURCE 600
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#ifdef SUNOS5
#include <sys/statvfs.h>
#endif
#include <sys/utsname.h>
#include <sys/wait.h>

#include <fcntl.h>

#define MAX_USER_LENGTH 33   /* 32 +1 for \0 */
#define MAX_PATH_LENGTH 4096

/*
 * Global variables
 */
char *turninversion = "1.4";

char rundir[MAX_PATH_LENGTH];
char user_name[MAX_USER_LENGTH];

char *assignment, *class;
int  class_uid, user_uid;

char *finalfile;

int maxfiles	=  100;
int maxkbytes	= 1000;
int maxturnins	=   10;
int binary	=    0;

int nfiles, nkbytes, nsymlinks;

char *assignment_path, *tmp_assignment_path, *assignment_file, *tmp_assignment_file;
int saveturnin;
#define MAX_FILENAME_LENGTH 256

char *tarcmd;
char *compresscmd;
char *mvcmd;

typedef struct fdescr {
	char		  *f_name;
	int		   f_flag;
	time_t		   f_mtime;
	size_t		   f_size;
	char		  *f_symlink;
	struct fdescr *f_link;
} Fdescr;

/*
 * f_flag values
 */
#define F_OK		0
#define F_NOTFILE	1
#define F_BINFILE	2
#define F_TMPFILE	3
#define F_RCSFILE	4
#define F_NOTOWNER	5
#define F_DOTDOT	6
#define F_ROOTED	7
#define F_NOEXIST	8
#define F_COREFILE	9
#define F_PERM		10
#define F_DIRECTORY	11
#define F_NOTDIR	12
#define F_SYMLINK	13

Fdescr *fileroot, *filenext;

/*
 * get arguments: assignment, class, list of files-and-directories
 */
void usage() {
	fprintf(stderr, "Usage: turnin assignmt@class files-and-directories ...\n");
	exit(1);
}

char * timestamp(time_t clock) {
	char *b = (char *) malloc(16);
	struct tm *t = localtime(&clock);

	sprintf(b, "%02d/%02d/%02d %02d:%02d", t->tm_mon+1, t->tm_mday, t->tm_year % 100,
	        t->tm_hour, t->tm_min);
	return b;
}

void be_class() {
	if (seteuid(0) == -1) {
		perror("seteuid root");
		exit(1);
	}
/*
 */
	if (seteuid(class_uid) == -1) {
		perror("seteuid");
		exit(1);
	}
}

void be_user() {
	if (seteuid(0) == -1) {
		perror("seteuid root");
		exit(1);
	}
/*
 */
	if (seteuid(user_uid) == -1) {
		perror("seteuid");
		exit(1);
	}
}

void wanttocontinue() {
	char b[10], c;

	fprintf(stderr, "\n*** Do you want to continue? ");

	if (fgets(b, sizeof(b)-1, stdin) == NULL)
		exit(1);
	c = tolower(b[0]);
	while (c != 'y' && c != 'n') {
		(void) clearerr(stdin);
		fprintf(stderr, "\n*** Please enter 'y' or 'n'.\n");
		fprintf(stderr, "\n*** Do you want to continue? ");
		if (fgets(b, sizeof(b)-1, stdin) == NULL)
			exit(1);
		c = tolower(b[0]);
	}
	if (c == 'n') {
		fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
		exit(1);
	}
}

void setup(char *arg) {
	struct passwd *pwd;
	struct stat statb;
	char buf[256], *p;
	FILE *fd;

	char keyword[256];
	int n;
	int i, warn;

	/* Check if it was compiled/setup properly */
	if (geteuid() != 0)
	{
		fprintf(stderr, "turnin must be setuid.  Ask for help.\n");
		exit(1);
	}

	user_uid = getuid();

	if (getlogin_r(user_name, MAX_USER_LENGTH) != 0) {
		fprintf(stderr, "Cannot get user's login (uid %d)\n", user_uid);
		exit(1);
	}

	if (!getcwd(rundir, MAX_PATH_LENGTH)) {
		perror("getcwd");
		exit(1);
	}

	assignment = arg;
	class = strchr(assignment, '@');

	if (!class)
		usage();

	*class++ = '\0';

	pwd = getpwnam(class);
	if (!pwd) {
		fprintf(stderr, "turnin: '%s' not valid\n", class);
		exit(1);
	}

	class_uid = pwd->pw_uid;

	if (!class_uid) {
		fprintf(stderr, "turnin: Cannot turnin to root\n");
		exit(1);
	}

	/* assignment path is in the class' home directory */
	/* plus 2 is for adding the '/' and '\0' */
	i = strlen(pwd->pw_dir) + strlen("/TURNIN/")  + strlen(assignment) + 2;

	if ( i > (MAX_PATH_LENGTH - MAX_FILENAME_LENGTH) ) {
		fprintf(stderr, "turnin: turnin path longer than %d\n", MAX_PATH_LENGTH);
		exit(1);
	}

	assignment_path = (char *)malloc(i + MAX_FILENAME_LENGTH);
	strcpy(assignment_path, pwd->pw_dir);
	strcat(assignment_path, "/TURNIN/");
	strcat(assignment_path, assignment);
	strcat(assignment_path, "/");
	assignment_file = assignment_path + i - 1;

	/* To prevent ..(/folder) and .(/folder) this check was added -- bboe */
	if (strstr(assignment_path, "./") != NULL) {
		fprintf(stderr, "turnin: \"..\" and \".\" not allowed in project name\n");
		exit(1);
	}

	/* 5 is the length of "/tmp/" + 1 for the \0 */
	tmp_assignment_path = (char *)malloc(5 + MAX_FILENAME_LENGTH + 1);
	strcpy(tmp_assignment_path, "/tmp/");
	/* 5 is the length of "/tmp/" */
	tmp_assignment_file = tmp_assignment_path + 5;

	/*
	 * Check on needed system commands
	 */
	if (access("/bin/tar", X_OK) == 0)
		tarcmd = "/bin/tar";
	else {
		fprintf(stderr, "Cannot find tar command\n");
		exit(1);
	}

	if (access("/bin/gzip", X_OK) == 0) {
		compresscmd = "/bin/gzip";
	} else {
		fprintf(stderr, "Cannot find gzip command\n");
		exit(1);
	}

	assignment_file[0] = '.';
	assignment_file[1] = 0;

	/* checks for final (class) directory */
	be_class();

	if (lstat(assignment_path, &statb) == -1) {
		perror(assignment_path);
		exit(1);
	}

	if (statb.st_uid != class_uid) {
		fprintf(stderr, "%s not owned by %s.  ask for help.\n",
		        assignment_path, class);
		exit(1);
	}

	/* Is it a directory ? */
	if ((statb.st_mode & S_IFMT) != S_IFDIR) {
		fprintf(stderr, "%s not a directory.  ask for help.\n",
		        assignment_path);
		exit(1);
	}

	/* Does the class have RWX permissions ? */
	if ((statb.st_mode & S_IRWXU) != S_IRWXU) {
		fprintf(stderr, "%s has bad mode. ask for help.\n",
		        assignment_path);
		exit(1);
	}

	/* Check if the assignment is locked */
	strcpy(assignment_file, "LOCK");
	if (lstat(assignment_path, &statb) != -1) {
		*assignment_file = 0;
		fprintf(stderr, "Assignment directory locked: %s. asked for help\n",
		        assignment_path);
		exit(1);
	}

	/* checks for tmp directory */
	if (lstat(tmp_assignment_path, &statb) == -1) {
		perror(tmp_assignment_path);
		exit(1);
	}
	/* Is it a directory ? */
	if ((statb.st_mode & S_IFMT) != S_IFDIR) {
		fprintf(stderr, "%s not a directory.  ask for help.\n",
		        tmp_assignment_path);
		exit(1);
	}
	/* Does the class have RWX permissions ? */
	if ((statb.st_mode & S_IRWXU) != S_IRWXU) {
		fprintf(stderr, "%s has bad mode. ask for help.\n",
		        tmp_assignment_path);
		exit(1);
	}

	/*
	 * Check limits file
	 */
	strcpy(assignment_file, "LIMITS");
	fd = fopen(assignment_path, "r");
	if (fd) {
		while (fgets(buf, sizeof(buf)-1, fd) == buf) {
			if ( (p = strchr(buf, '#')) )
				*p-- = 0;
			else
				p = buf + strlen(buf) - 1;

			while (p >= buf && isspace(*p))
				--p;

			if (p == buf-1)
				continue;

			p[1] = 0; /* Remove trailing spaces */

			/* Remove spaces from the start */
			for (p = buf;  *p && isspace(*p);  p++) ;

			warn = 0;
			if (sscanf(buf, "%s %d", keyword, &n) != 2) {
				warn = 1;
			} else if (strcasecmp(keyword, "maxfiles") == 0) {
				maxfiles = n;
			} else if (strcasecmp(keyword, "maxkbytes") == 0) {
				maxkbytes = n;
			} else if (strcasecmp(keyword, "maxturnins") == 0) {
				maxturnins = n;
			} else if (strcasecmp(keyword, "binary") == 0) {
				binary = n;
			} else {
				warn = 1;
			}
			if (warn) {
				fprintf(stderr,"Warning: undecipherable LIMITS file\n");
				fprintf(stderr,"This is harmless, but mention to instructor\n");
			}
		}
		(void) fclose(fd);
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
		(void) fclose(fd);
		wanttocontinue();
	}

	/*
	 * Check for multiple turnins
	 */
	strcpy(assignment_file, user_name);
	strcat(assignment_file, ".tgz");
	finalfile = strdup(assignment_path);

	if (lstat(finalfile, &statb) != -1) {
		fprintf(stderr, "\n\n*** You have already turned in %s\n", assignment);
		wanttocontinue();

		/* compute next version name */
		for (saveturnin = 1;  saveturnin <= maxturnins;  saveturnin++) {
			sprintf(assignment_file, "%s-%d.tgz", user_name, saveturnin);
			if (lstat(assignment_path, &statb) == -1)
				break;
		}

		if (saveturnin == maxturnins) {
			fprintf(stderr, "*** MAX TURNINS REACHED FOR %s (%d) ***\n",
			        assignment, maxturnins);
			fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
			exit(1);
		}
	}

	be_user();
}

int isbinaryfile(char *s) {
	char buf[256];
	char *p;
	int n, f, c;

	f = open(s, 0);
	if (f == -1) {perror(s); exit(1);}

	n = read(f, buf, sizeof(buf));
	if (n == -1) {perror(s); exit(1);}
	(void) close(f);

	p = buf;
	while (n-- > 0) {
		c = *p++ & 0xff;
		if (c == 0) return 1;
		/* The following works only for ascii. Not valid for
		 * unicode */
		/* if (c & 0x80) return 1; */
	}

	return 0;
}

void check_symlink(char *s, Fdescr *f) {
	char b[256], *p;
	int m, bl;
	struct stat statb;
	int must_be_dir;

	p = b + 255;
	while (p >= b) *p-- = 0;

	if (readlink(s, b, sizeof(b)) == -1) {
		perror(s);
		exit(1);
	}
	bl = strlen(b);

	if (b[0] == '/') {
		f->f_flag = F_ROOTED;
		return;
	}

	if (bl > 1  &&  b[0] == '.'  &&  b[1] == '.'  && (!b[2] || b[2]=='/')) {
		f->f_flag = F_DOTDOT;
		return;
	}
	m = bl - 2;
	for (p = strchr(b, '/');  p;  p = strchr(p+1, '/')) {
		if (p - b > m)
			break;
		if (p[1] != '.' || p[2] != '.')
			continue;
		if (p[3] == 0 || p[3] == '/') {
			/* have /..$  or /../ */
			f->f_flag = F_DOTDOT;
			return;
		}
	}

	if (lstat(b, &statb) == -1) {
		f->f_flag = F_NOEXIST;
		return;
	}

	if (statb.st_uid != user_uid) {
		f->f_flag = F_NOTOWNER;
		return;
	}

	must_be_dir = 0;
	/* Eat trailing slashes from directories */
	while (bl > 1 && b[bl-1] == '/') {
		b[bl-1] = 0;
		bl--;
		must_be_dir = 1;
	}

	if (must_be_dir && (statb.st_mode & S_IFMT) != S_IFDIR) {
		f->f_flag = F_NOTDIR;
		return;
	}

	if ((statb.st_mode & S_IFMT) == S_IFLNK) {
		check_symlink(b, f);
		return;
	}

	f->f_flag = F_SYMLINK;
	f->f_symlink = strdup(b);
	return;
}

void addfile(char *s) {
	struct stat statb;
	struct dirent *dp;
	DIR *dirp;
	Fdescr *f;
	char *p, *t;
	int n, sl, i;
	int must_be_dir;

	f = (Fdescr *) malloc(sizeof(Fdescr));
	memset((void *)f, 0, sizeof(Fdescr));

	sl = strlen(s);

	if (!fileroot) {
		fileroot = filenext = f;
	} else {
		filenext->f_link = f;
		filenext = f;
	}

	must_be_dir = 0;
	/* Eat trailing slashes from directories */
	while (sl > 1 && s[sl-1] == '/') {
		s[sl-1] = 0;
		sl--;
		must_be_dir = 1;
	}

	f->f_name = strdup(s);

	if (*s == '/') {
		f->f_flag = F_ROOTED;
		return;
	}

	if (*s == '#') {
		f->f_flag = F_TMPFILE;
		return;
	}

	if (s[sl-1] == '~') {
		f->f_flag = F_TMPFILE;
		return;
	}

	/* check for ".." in the path */
	if (sl > 1  &&  s[0] == '.'  &&  s[1] == '.'  &&  (!s[2] || s[2]=='/')) {
		f->f_flag = F_DOTDOT;
		return;
	}

	n = sl - 2;
	for (p = strchr(s, '/');  p;  p = strchr(p+1, '/')) {
		if (p - s > n)
			break;
		if (p[1] != '.' || p[2] != '.')
			continue;
		if (p[3] == 0 || p[3] == '/') {
			/* have /..$  or /../ */
			f->f_flag = F_DOTDOT;
			return;
		}
	}

	if (strcmp(s, "core") == 0) {
		f->f_flag = F_COREFILE;
		return;
	}

	if (lstat(s, &statb) == -1) {
		f->f_flag = F_NOEXIST;
		return;
	}

	if (statb.st_uid != user_uid) {
		f->f_flag = F_NOTOWNER;
		return;
	}

	if (must_be_dir && (statb.st_mode & S_IFMT) != S_IFDIR) {
		f->f_flag = F_NOTDIR;
		return;
	}

	if ((statb.st_mode & S_IFMT) == S_IFREG) {
		if ((statb.st_mode & S_IRUSR) != S_IRUSR)
			f->f_flag = F_PERM;
		else if (isbinaryfile(s))
			if ( binary ) {
				f->f_flag = F_OK;
				f->f_mtime = statb.st_mtime;
				f->f_size = statb.st_size;
			}
			else
				f->f_flag = F_BINFILE;
		else {
			f->f_mtime = statb.st_mtime;
			f->f_size = statb.st_size;
			f->f_flag = F_OK;
		}
		return;
	}

	/* If the symlink links to a symlink recurse */
	if ((statb.st_mode & S_IFMT) == S_IFLNK) {
		check_symlink(s, f);
		return;
	}

	if ((statb.st_mode & S_IFMT) != S_IFDIR) {
		f->f_flag = F_NOTFILE;
		return;
	}

	f->f_flag = F_DIRECTORY;

	dirp = opendir(s);
	if (!dirp) {
		f->f_flag = F_NOTDIR;
		return;
	}

	while ( (dp = readdir(dirp)) != NULL ) {
		p = dp->d_name;
		if (!(strcmp(p, ".") == 0) && !(strcmp(p, "..") == 0)) {
			i =  sl + 1 + strlen(p) + 1;
			t = (char *)malloc(i);
			strcpy(t, s);
			strcat(t, "/");
			strcat(t, p);
			addfile(t);
		}
	}

	(void) closedir(dirp);
}

/*
 * List all filenames that are to be excluded.
 * Return the number of files excluded.
 */
int warn_excludedfiles() {
	Fdescr *fp;
	char *msg = 0;
	int first = 1;

	for (fp = fileroot;  fp;  fp = fp->f_link) {
		switch (fp->f_flag) {
		case F_NOTFILE:  msg = "not a file, directory, or symlink"; break;
		case F_BINFILE:  msg = "binary file"; break;
		case F_TMPFILE:  msg = "temporary file"; break;
		case F_RCSFILE:  msg = "RCS file or directory"; break;
		case F_NOTOWNER: msg = "not owned by user"; break;
		case F_DOTDOT:   msg = "pathname contained '..'"; break;
		case F_ROOTED:   msg = "only relative pathnames allowed"; break;
		case F_NOEXIST:  msg = "does not exist"; break;
		case F_COREFILE: msg = "may not turnin core files"; break;
		case F_PERM:     msg = "no access permissions"; break;
		case F_NOTDIR:   msg = "error reading directory"; break;
		case F_DIRECTORY:msg = 0; break;
		case F_SYMLINK:  msg = 0; break;
		case F_OK:		 msg = 0; break;
		default:
			fprintf(stderr, "INTERNAL ERROR: %d f_flag UNKNOWN\n", fp->f_flag);
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
	int fatal = 0;
#ifdef SUNOS5
	struct statvfs fsbuf;
#endif

	for (fp = fileroot;  fp;  fp = fp->f_link) {
		if (fp->f_flag == F_SYMLINK)
			nsymlinks++;
		else if (fp->f_flag == F_OK) {
			nfiles++;
			nkbytes = nkbytes + (fp->f_size+1023)/1024;
		}
	}

	if (nfiles > maxfiles) {
		fprintf(stderr,
		        "A maximum of %d files may be turned in for this assignment.\n",
		        maxfiles);
		fprintf(stderr,
		        "You are attempting to turn in %d files.\n", nfiles);
		fatal++;
	}

	if (nkbytes > maxkbytes) {
		fprintf(stderr,
		        "A maximum of %d Kbytes may be turned in for this assignment.\n",
		        maxkbytes);
		fprintf(stderr,
		        "You are attempting to turn in %d Kbytes.\n", nkbytes);
		fatal++;
	}

#ifdef SUNOS5
	assignment_file[0] = '.';
	assignment_file[1] = 0;
	if (statvfs(assignment_path, &fsbuf) == -1) {
		perror("statvfs");
		fprintf(stderr, "WARNING: cannot check free space\n");
		return fatal;
	}

	freekbytes = (fsbuf.f_bfree*fsbuf.f_bsize/1024);
	if (freekbytes < nkbytes) {
		fprintf(stderr, "Insufficient free space on class disk.\n");
		fprintf(stderr, "Contact your instructor or TA.\n");
		fatal++;
	}
#endif

	return fatal;
}


/*
 * For each file that will actually be turned in, print the
 * filename and modification date.  Make special notations for
 * symbolic links.
 */
void printverifylist() {
	Fdescr *f;
	int n = 0;
	char *msg[2];

	fprintf(stderr, "\nThese are the regular files being turned in:\n\n");
	fprintf(stderr, "\t    Last Modified   Size   Filename\n");
	fprintf(stderr, "\t    -------------- ------  -------------------------\n");

	for (f = fileroot;  f;  f = f->f_link) {
		if (f->f_flag != F_OK)
			continue;
		n++;
		fprintf(stderr, "\t%2d: %s %6u  %s\n",
		        n, timestamp(f->f_mtime), (unsigned int)f->f_size, f->f_name);
	}

	msg[0] = "\nThese are the symbolic links being turned in:\n";
	msg[1] = "(Be sure the files referenced are turned in too)\n";

	for (f = fileroot;  f;  f = f->f_link) {
		if (f->f_flag != F_SYMLINK)
			continue;
		if (msg[0]) fprintf(stderr, "%s%s", msg[0], msg[1]);
		msg[0] = 0;
		n++;
		fprintf(stderr, "\t%2d: %s -> %s\n", n, f->f_name, f->f_symlink);
	}
}

/*
 * make the tar image in a temporary file in the assignment directory.
 *
 *	su:user tar cpf - file-list | su:class compress  > tempfile in assignmentdir
 */
char *tempfile;

void maketar() {
	int ofd, pfd[2];
	int childpid, childstat;
	int tarpid, tarstat;
	int comppid, compstat;
	int failed;

	char **targvp, **tvp;
	int nleft;

	Fdescr *fp;

	/*
	 * build the tar argument list
	 */
	tvp = targvp = (char **) malloc((3+nfiles+nsymlinks+1)*sizeof(char *));
	tvp[0] = "tar";
	tvp[1] = "cvf";
	tvp[2] = "-";
	tvp += 3;

	nleft = nfiles + nsymlinks;

	for (fp = fileroot;  fp;  fp = fp->f_link) {
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
	 * setup tempfile name
	 */
	sprintf(tmp_assignment_file, "#%s-%05d", user_name, getpid());
	tempfile = strdup(tmp_assignment_path);

	be_class();
	ofd = open(tempfile, O_CREAT|O_EXCL|O_WRONLY, 0600);

	if (ofd == -1) {
		perror(tempfile);
		fprintf(stderr, "Could not open temporary file: %s\n", tempfile);
		fprintf(stderr, "\n**** ABORTING TURNIN ****\n");
		unlink(tempfile);
		exit(1);
	}

	be_user();

	/*
	 * Do the actual tar
	 */
	failed = 0;
	childpid = fork();

	if (!childpid) {	/* in child */
		if (pipe(pfd) == -1) {perror("pipe"), exit(1);}

		tarpid = fork();
		if (!tarpid) {
			if (pfd[1] != 1) {
				dup2(pfd[1], 1);
				(void) close(pfd[1]);
			}
			(void) close(pfd[0]);
			execv(tarcmd, targvp);
			perror("tarcmd");
			_exit(1);
		}
		comppid = fork();
		if (!comppid) {
			if (pfd[0] != 0) {
				dup2(pfd[0], 0);
				(void) close(pfd[0]);
			}
			(void) close(pfd[1]);
			if (ofd != 1) {
				dup2(ofd, 1);
				(void) close(ofd);
			}
			execl(compresscmd, "gzip", (char*)NULL);
			perror(compresscmd);
			_exit(1);
		}
		(void) close(pfd[0]);
		(void) close(pfd[1]);

		wait(&tarstat);
		if (tarstat) failed = -1;
		wait(&compstat);
		if (compstat) failed = -1;
		_exit(failed);
	}
	wait(&childstat);

	if (childstat) {
		fprintf(stderr, "Subprocesses returned FAILED status: %x\n", childstat);
		fprintf(stderr, "Contact instructor or TA\n");
		(void) close(ofd);
		unlink(tempfile);
		exit(1);
	}

	(void) close(ofd);
}

void movetar() {
	int mvpid, mvstat;

	mvcmd = "/bin/mv";

	sprintf(assignment_file, "%s.tgz", user_name);
	finalfile = strdup(assignment_path);

	be_class();

	if (saveturnin) {
		sprintf(assignment_file, "%s-%d.tgz", user_name, saveturnin);
		/*
		  x = rename(finalfile, assignment_path);
		  if (x < 0) { perror("rename"); exit(1); }
		*/
	}

	/* can't use rename() over different file systems ie. /tmp -> /cs/class */
	/*
	  x = rename(tempfile, finalfile);
	  if (x < 0) { perror("rename"); exit(1); }
	*/
	/* mv file from temp location to final location */
	mvpid = fork();
	if (!mvpid) {
		execl(mvcmd, "mv", tempfile, assignment_path, NULL);
		perror(mvcmd);
		_exit(1);
	}
	wait(&mvstat);
	if (mvstat) {
		fprintf(stderr, "Move Subprocesses returned FAILED status: %x\n", mvstat);
		fprintf(stderr, "Contact instructor or TA\n");
		unlink(tempfile);
		exit(1);
	}

	be_user();
}

/*
 * write the log entry
 *
 *		whichturnin,  user, date, time, number-of-files, user-directory
 *
 */
void writelog() {
	char b[5120];
	int fd, n, x;

	time_t now = time(0);

	snprintf(b, 5120, "tv%s: %-8s %s %3d %s\n",
	         turninversion, user_name, timestamp(now), nfiles + nsymlinks, rundir);

	n = strlen(b);

	strcpy(assignment_file, "LOGFILE");

	be_class();

	fd = open(assignment_path, O_CREAT|O_WRONLY|O_APPEND|O_SYNC, 0600);
	if (fd == -1) {
		perror(assignment_path);
		fprintf(stderr, "WARNING:  Could not open assignment log file\n");
	} else {
		x = fsync(fd); if (x == -1) perror("fsync");

		if ( write(fd, b, n) == -1 ) {
			fprintf(stderr, "Failed to write log");
			exit(1);
		}

		x = fsync(fd); if (x == -1) perror("fsync");
		(void) close(fd);
	}

	be_user();
}

int main(int argc, char* argv[]) {
	if (argc < 3)
		usage();

	/* Disable signals BEFORE we become class or root or whatever... */
	(void) sigignore(SIGINT);
	(void) sigignore(SIGTSTP);
	(void) sigignore(SIGQUIT);
	(void) sigignore(SIGHUP);
	(void) sigignore(SIGTTIN);
	(void) sigignore(SIGTTOU);

	setup(argv[1]);

	argv += 2; argc -= 2;
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
		fprintf(stderr, "%s %d+%d (files+symlinks) [%dKB] for %s to %s\n",
		        "You are about to turnin",
		        nfiles, nsymlinks, nkbytes, assignment, class);
	} else {
		fprintf(stderr, "%s %d files [%dKB] for %s to %s\n",
		        "You are about to turnin", nfiles, nkbytes, assignment, class);
	}

	wanttocontinue();

	maketar();

	movetar();
	writelog();

	fprintf(stderr,"\n*** TURNIN OF %s TO %s COMPLETE! ***\n",assignment,class);
	exit(0);
}
