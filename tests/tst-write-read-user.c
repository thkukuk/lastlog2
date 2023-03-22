/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2023, Thorsten Kukuk <kukuk@suse.com>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

/* Test case:
   Create an entry, rename that entry, and try to read the old and
   new entry again. Reading the old entry should fail.
*/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lastlog2.h"

static int
test_args (const char *db_path, const char *user, int64_t ll_time,
	   const char *tty, const char *rhost)
{
  char *error = NULL;
  int64_t res_time;
  char *res_tty = NULL;
  char *res_rhost = NULL;

  if (ll2_write_entry (db_path, user, ll_time, tty, rhost, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "ll2_write_entry failed\n");
      return 1;
    }

  if (ll2_read_entry (db_path, user, &res_time, &res_tty, &res_rhost, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Unknown error reading database %s", db_path);
      return 1;
    }

  if (ll_time != res_time)
    {
      fprintf (stderr, "Wrong time: got %lld, expect %lld\n",
	       (long long int)res_time, (long long int)ll_time);
      return 1;
    }

  if ((tty == NULL && res_tty != NULL) ||
      (tty != NULL && res_tty == NULL) ||
      (tty != NULL && res_tty != NULL && strcmp (tty, res_tty) != 0))
    {
      fprintf (stderr, "Wrong tty: got %s, expect %s\n", tty, res_tty);
      return 1;
    }

  if ((rhost == NULL && res_rhost != NULL) ||
      (rhost != NULL && res_rhost == NULL) ||
      (rhost != NULL && res_rhost != NULL && strcmp (rhost, res_rhost) != 0))
    {
      fprintf (stderr, "Wrong rhost: got %s, expect %s\n", rhost, res_rhost);
      return 1;
    }

  return 0;
}

int
main(void)
{
  const char *db_path = "tst-write-read-user.db";

  if (test_args (db_path, "user1", time (NULL), "test-tty", "localhost") != 0)
    return 1;
  if (test_args (db_path, "user2", 0, NULL, NULL) != 0)
    return 1;
  if (test_args (db_path, "user3", time (NULL), NULL, NULL) != 0)
    return 1;
  if (test_args (db_path, "user4", time (NULL), "test-tty", NULL) != 0)
    return 1;
  if (test_args (db_path, "user5", time (NULL), NULL, "localhost") != 0)
    return 1;

  return 0;
}
