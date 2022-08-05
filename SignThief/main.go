package main

import (
	"github.com/Binject/debug/pe"
	"io/ioutil"
	"log"
	"os"
)

func savecert(sigexe string, dstcert string) {
	cert := getcert(sigexe)
	ioutil.WriteFile(dstcert, cert, os.ModePerm)
}

func getcert(sigexe string) []byte {
	pefile, _ := pe.Open(sigexe)
	defer pefile.Close()
	if string(pefile.CertificateTable) == "" {
		log.Fatal("ERROR!Certfile Not signed! ")
	}
	return pefile.CertificateTable
}

func writecertfromdisk(outputloc string, inputloc string, cert string) {
	certfile, _ := ioutil.ReadFile(cert)
	appendcert(outputloc, inputloc, certfile)
}

func writecertfromexe(outputloc string, inputloc string, certfileloc string) {
	certfile := getcert(certfileloc)
	appendcert(outputloc, inputloc, certfile)
}

func appendcert(outputloc string, inputloc string, cert []byte) {
	pefile, _ := pe.Open(inputloc)
	defer pefile.Close()
	pefile.CertificateTable = cert
	pefile.WriteFile(outputloc)
}

func main(){
	writecertfromexe( "00-HelloTide-sign.exe","00-HelloTide.exe","sign.exe")
}