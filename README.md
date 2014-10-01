turnin
======

```turnin``` is a unix utility that allows students to turn in their
homework from the School/Univerity's computers.

## Setup

The ```root``` user needs to download (```git clone```) all files in
this repository and run ```make; make install; make clean```.  Please
note that this cannot be done with ```sudo(8)``` and needs access to
the actual ```root``` user.  This series of ```bash(1)``` commands
will compile, place, and activate the ```turnin``` binary.  It will
also create a ```man(1)``` entry with further instructions for both
professors and students.

### Requirements
* ```gcc```
* ```make```
* ```tar```
* ```libssl-dev``` on debian
* ```git``` (For download and updates)

## Usage for professors/TAs

A set of unix computers is required that both classes and students
have access to from a unique unix account.  Each class has a home
directory and it can create a folder named ```TURNIN```.  If this
folder is available then other unix accounts can turn in exercises to
it.  In order to create an assignment, i.e. ```Homework1```, the class
has to create a folder inside the ```TURNIN``` folder with the name
```Homework1```.  Please refer to the manpage (```man turnin```) for
further details.

## History

The program was first written in 1993 and then updated to fix some
bugs and security flaws. The original repository can be found
[here](https://github.com/ucsb-cs/turnin). It has been created for
SunOS 5 but then with updates it was able to run in modern operating
systems like debian as well. On September 1st, 2014, Foivos S. Zakkak
and Antonios A. Chariton (zakkak & DaKnOb) forked the original
repository and created a new version of ```turnin``` that is more
secure (it patches several exploitable vulnerabilities found in the
original code, minimizes attack surface), faster and with partly
extended functionality. On September 6th, 2014, official support for 
SunOS5 has been dropped. A few days later, both projects went under the
GPL v3 License after contacting all the authors and agreeing to it.

## Development

### Pull requests

Pull requests are always welcome.  Please respect the coding style and
stay consistent.  In your pull request you should describe exactly
what it solves and in the case that you use some complex
logic/algorithm please describe it as well.

### New release

To create a new release first create an annotated tag (it would be
nice if it is also signed), i.e.,

```
git tag -s -m "Release v2.2.2" v2.2.2
```

and then push the tags

```
git push --tags
```

#### Versions

The version for development builds is retrieved automatically through
the command `git describe` at compilation time (see target `version`
in the Makefile).

However since the `.git` directory is not contained in the release
archives we still need to manually upgrade the version in the source
files before a release.
