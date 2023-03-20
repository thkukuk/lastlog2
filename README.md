# lastlog2

**Y2038 safe version of lastlog**

## Background

`lastlog` reports the last login of a given user or of all users who did ever login on a system.

The standard `/var/log/lastlog` implementation using `lastlog.h` from glibc uses a **32bit** **time_t** in `struct lastlog` on bi-arch systems like x86-64 (so which can execute 64bit and 32bit binaries). So even if you have a pure 64bit system, on many architectures using glibc you have a Y2038 problem.

For background on the Y2038 problem (32bit time_t counter will overflow) I suggest to start with the wikipedia [Year 2038 problem](https://en.wikipedia.org/wiki/Year_2038_problem) article.

There is also a more [technical document](https://github.com/thkukuk/utmpx/blob/main/Y2038.md), describing the problem in more detail, which also contains a list of affected packages. And a more highlevel blog "[Y2038, glibc and /var/log/lastlog on 64bit architectures](https://www.thkukuk.de/blog/Y2038_glibc_lastlog_64bit/)"

Additional, `/var/log/lastlog` can become really huge if there are big UIDs in use on the system. Since it is a sparse file, this is normally not a problem, but depending on the filesystem or the tools used for backup, this can become a real problem.

Since there are only few applications which really support `lastlog`, the data is also not always correct.

## lastlog2

`lastlog2` tries to solve this problems:

* It's using sqlite3 as database backend.
* Data is only collected via a PAM module, so that every tools can make use of it, without modifying existing packages.
* The output is as compatible as possible with the old lastlog implementation.
* The old `/var/log/lastlog` file can be imported into the new database.
* The size of the database depends on the amount of users, not how big the biggest UID is.

**IMPORTANT** To be Y2038 safe on 32bit architectures, the binaries needs to be build with a **64bit time_t**. This should be the standard on 64bit architectures.

The package constists of a library, PAM module and an application:

* `liblastlog2.so.0` contains all high level functions to manage the data.
* `pam_lastlog2.so` shows the last login of a user and stores the new login into the database.
* `lastlog2` will display the last logins for all users, who did ever login.

By default the database will be written as `/var/lib/lastlog/lastlog2.db`.

## Configuration

The `pam_lastlog2.so` module will be added in the `session` section of the service, which should display the last login message and store the new data.
On openSUSE Tumbleweed and MicroOS, the following line needs be added at the end of `/etc/pam.d/common-session`:

```
session optional pam_lastlog2.so
```

This line will create a new entry in the database for every user if an application calls the PAM framework.
