1. Contents
------------

This source tree contains a simple module program and a binary code to
test the system call interception of 'open()' system call.

testmod.c 	-  Module source code.
testprog.c 	-  A simple test program.
Makefile	-  Instructions to compile the module.
README.md	-  Detailed information about the module.

2. Description
---------------

testmod.c  :  This module code prevents access to a particular file (e.g. "/file1") 
	      which is specified as a module parameter with 'insmod'.
	      When the module is loaded, every access to this file would result
	      into error. All other files can be accessed without any issue.
	      When the module is unloaded, the access to "/file1" is restored.

testprog.c :  This opens a file passed as an argument.
	      The argument should be the same as that of testmod.
	      If the module (testmod.ko) is loaded, then open would fail,
	      else it would succeed.
	      This tests the functionality of the module.

In addition, other commands on that file such as 'ls -l', vi, cat would also fail.

3. System Requirements:
-----------------------

This code would run on linux kernel versions 2.6.*.

4. Building
-----------

The Makefile facilitates to build the kernel module and
produces 'testmod.ko' using 'make' command.

To build the test program binary, execute following command:

# gcc -o testprog testprog.c

5. Testing
-----------

1. Load the new module with following command:

# insmod testmod.ko filename="/file1"

Here, the module parameter is 'filename' and its value is "/file1"
After it is successfully loaded, the 'open' system call is intercepted,
which means that all accesses to the file "/file1" are denied.

2. Now, execute the test program with following command:

# ./testprog /file1

It should display the error "Open failed.".

3. However, it should succeed for all other files.

# ./testprog /file2

It should give message "Open succeeded."

4. Now unload the module

# rmmod testmod

After this, there will be no interception of 'open' syscall.

5. Now try to access "/file1" again.

# ./testprog /file1

It should succeed.
