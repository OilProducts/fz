# Example Fuzz Targets

This directory contains small programs used as fuzzing examples for the
project.  Each subdirectory holds an individual target along with its build
files and an optional script to run the fuzzer.

- `target1` – simple program that reads from `stdin` without bounds checking.
