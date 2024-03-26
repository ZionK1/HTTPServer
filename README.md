#Assignment 2 directory

This directory contains source code and other files for Assignment 2.

Use this README document to store notes about design, testing, and
questions you have while developing your assignment.

Question 1: How can I modularize the different tasks for this assignment like parsing/handling the request and get/put?

Question 2: Can I include other files that include my own helper functions to accomplish this where these different
modules share data? If so, how can I achieve data sharing across my modules?

Update: Upon looking at the regex practica, I've decided to implement a separate request struct for when parsing the request

Links used for regex:
stackoverflow.com/questions/1247762/regex-for-all-printable-characters

Used ChatGPT for inspiration in my helper function my_read for the general structure (ended up changing body to use strstr())

Linked used for debugging (errno):
https://stackoverflow.com/questions/46013418/how-to-check-the-value-of-errno
https://stackoverflow.com/questions/15798450/open-with-o-creat-was-it-opened-or-created
