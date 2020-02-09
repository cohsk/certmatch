// A utility program to do a binary comparison of two certificate files
// using golang and the standard golang x509 parsing algorithm
//
// Version 1.0
//
// January 2020
//
// Steve Klosky
// steve.klosky@cohesity.com
//
//

package main

import (
	"crypto/x509"
	"fmt"
	"os"
)

func main() {
	inargs := os.Args[1:]

	// add input args checking here

	fmt.Printf("certificate file 1 - ")
	fmt.Printf(inargs[0])
	fmt.Printf("\n")
	fmt.Printf("certificate file 2 - ")
	fmt.Printf(inargs[1])
	fmt.Printf("\n")

	// read certificate file 1 and parse for key fields
	// common name and serial number

	certCerFile, err := os.Open(inargs[0])

	// add file open error handling here

	derBytes := make([]byte, 3000)

	count, err := certCerFile.Read(derBytes)

	certCerFile.Close()

	// trim the bytes to actual length in call
	cert1, err := x509.ParseCertificate(derBytes[0:count])

	if err != nil {
		fmt.Printf("certificate 1 parse error")
	}

	fmt.Printf("Certificate 1 Common Name = %s\n", cert1.Subject.CommonName)
	fmt.Printf("Certificate 1 Serial Number = %s\n", cert1.SerialNumber.String())

	// read certificate file 2 and parse for key fields
	// common name and serial number

	certCerFile2, err := os.Open(inargs[1])

	// add file open error handling here

	derBytes2 := make([]byte, 3000)

	count2, err := certCerFile2.Read(derBytes2)

	certCerFile2.Close()

	// trim the bytes to actual length in call
	cert2, err := x509.ParseCertificate(derBytes2[0:count2])

	if err != nil {
		fmt.Printf("certificate 2 parse error")
	}

	fmt.Printf("Certificate 2 Common Name = %s\n", cert2.Subject.CommonName)
	fmt.Printf("Certificate 2 Serial Number = %s\n", cert2.SerialNumber.String())

	// Binary compare the two serial numbers

	if cert1.SerialNumber.Cmp(cert2.SerialNumber) != 0 {
		fmt.Printf("MISMATCH -- Serial Numbers DO NOT Match!\n")
	} else {
		fmt.Printf("MATCH -- Serial Numbers Match!\n")
	}

}
