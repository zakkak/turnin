turnin
======

```turnin``` is a unix utility that allows students to turn in their homework from the School/Univerity's computers.

<h2>Setup</h2>
A set of unix computers is required that both classes and students have access to from a unique unix account. 
Each class has a home directory and it can create a folder named ```TURNIN```. If this folder is available
then other unix accounts can submit to it. In order to create an assignment, i.e. Homework1, the class has to create
a folder inside the ```TURNIN``` folder with the name ```Homework1```. The ```root``` user needs to download all
files in this repository and run ```make;make install;make clean```. Please note that this cannot be done with ```sudo(8)``` and needs access to the actual root user. This series of ```bash(1)``` commands will 
compile, place and activate the ```turnin``` binary. It will also create a ```man(1)``` entry with further 
instructions for both professors and students.
<h3>Requirements</h3>
* ```git```
* ```gcc```
* ```make```
* ```tar```
* ```libssl-dev``` on debian
<br/>
<h2>History</h2>
The program was first written in 1993 and then updated to fix some bugs or security flaws. The original
repository can be found <a href="https://github.com/ucsb-cs/turnin">here</a>. It has been created for 
SunOS 5 but then with updates it was able to run in modern operating systems like debian as well. On
September 1st, 2014, Foivos S. Zakkak and Antonios A. Chariton (zakkak & DaKnOb) forked the original repository
and created a new version of ```turnin``` that is more secure (it patches several exploitable vulnerabilities
found in the original code, minimizes attack surface), faster and with partly extended functionality. A few
days later, both projects went under the GPL v3 License after contacting all the authors and agreeing to it.
