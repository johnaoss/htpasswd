// htpasswd - Manage user files for basic authentication
//
// Description:
//
// htpasswd is used to create and update the flat-files used to store usernames and password for basic authentication
// of HTTP users. If htpasswd cannot access a file, such as not being able to write to the output file or  not  being
// able to read the file in order to update it, it returns an error status and makes no changes.
//
// Resources available from the Apache HTTP server can be restricted to just the users listed in the files created by
// htpasswd. This program can only manage usernames and passwords stored in a flat-file. It can encrypt  and  display
// password  information for use in other types of data stores, though. To use a DBM database see dbmmanage or htdbm.
//
// htpasswd encrypts passwords using either bcrypt, a version of MD5 modified  for  Apache,  SHA1,  or  the  system's
// crypt()  routine.  Files  managed by htpasswd may contain a mixture of different encoding types of passwords; some
// user records may have bcrypt or MD5-encrypted passwords while others in the same file may have passwords encrypted
// with crypt().
// This  manual page only lists the command line arguments. For details of the directives necessary to configure user
// authentication in httpd see the Apache manual, which is part of  the  Apache  distribution  or  can  be  found  at
// http://httpd.apache.org/.
//
// See Also:
//
// man(1), man-pages(7)
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	flag "github.com/spf13/pflag"

	"github.com/johnaoss/htpasswd/apr1"
)

const (
	ErrFile = 1 + iota
	ErrArguments
	ErrVerifyPassword
	ErrInterrupt
	ErrTooLong
	ErrIllegalCharacters
	ErrInvalidFormat
)

var (
	// Unique
	createFile  bool
	printOutput bool
	verify      bool
	delete      bool

	// Important Function Flags
	cliPassword   bool
	stdinPassword bool

	// Encryption Flags
	useMd5       bool
	useBcrypt    bool
	useNoEncrypt bool
	useSHA       bool
	useCrypt     bool
	bcryptCost   int

	// Groups
	uniqueFlags = [4]bool{createFile, printOutput, verify, delete}
	argFormats  = [2]bool{printOutput, cliPassword}
)

const (
	usageStr = `
	Usage:
		htpasswd [-cimBdpsDv] [-C cost] passwordfile username
		htpasswd -b[cmBdpsDv] [-C cost] passwordfile username password

		htpasswd -n[imBdps] [-C cost] username
		htpasswd -nb[mBdps] [-C cost] username password
	-c  Create a new file.
	-n  Don't update file; display results on stdout.
	-b  Use the password from the command line rather than prompting for it.
	-i  Read password from stdin without verification (for script usage).
	-m  Force MD5 encryption of the password (default).
	-B  Force bcrypt encryption of the password (very secure).
	-C  Set the computing time used for the bcrypt algorithm
		(higher is more secure but slower, default: 5, valid: 4 to 31).
	-d  Force CRYPT encryption of the password (8 chars max, insecure).
	-s  Force SHA encryption of the password (insecure).
	-p  Do not encrypt the password (plaintext, insecure).
	-D  Delete the specified user.
	-v  Verify password for the specified user.
	On other systems than Windows and NetWare the '-p' flag will probably not work.
	The SHA algorithm does not use a salt and is less secure than the MD5 algorithm.
	`
)

func parseFlags() {
	flag.Usage = func() {
		fmt.Println(usageStr)
	}
	flag.BoolVarP(&createFile, "create", "c", false, "")
	flag.BoolVarP(&printOutput, "print", "n", false, "")
	flag.BoolVarP(&verify, "verify", "v", false, "")
	flag.BoolVarP(&delete, "delete", "D", false, "")
	flag.BoolVarP(&cliPassword, "passargs", "b", false, "")
	flag.BoolVarP(&stdinPassword, "passstdin", "i", false, "")
	flag.BoolVarP(&useMd5, "md5", "m", true, "")
	flag.BoolVarP(&useBcrypt, "bcrypt", "B", false, "")
	flag.BoolVar(&useNoEncrypt, "p", false, "")
	flag.BoolVar(&useSHA, "s", false, "")
	flag.BoolVar(&useCrypt, "d", false, "")
	flag.IntVar(&bcryptCost, "C", 5, "")
	flag.Parse()

	var incorrectUsage bool

	// incorrect flag
	if cliPassword && stdinPassword {
		incorrectUsage = true
	} else if printOutput && (delete || verify || createFile) {
		incorrectUsage = true
	}

	if incorrectUsage {
		flag.Usage()
		os.Exit(ErrArguments)
	}

}

func main() {
	// handle interrupts
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Exit(ErrInterrupt)
	}()

	parseFlags()

	// basic test for hash.
	// important to note these wont be the same due to randomly generated hashes.
	if printOutput && cliPassword {
		hash, err := apr1.Hash(flag.Arg(1), "")
		if err != nil {
			log.Fatalf("%s\n", err.Error())
		}
		fmt.Printf("%s:%s\n\n", flag.Arg(0), hash)
	}
}
