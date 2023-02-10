package parser

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io"
	"log"
	"net/http"
)

func ParseXml(in any, host string, path string, twfid string) (string, bool) {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	addr := "https://" + host + path
	req, err := http.NewRequest("GET", addr, nil)
	req.Header.Set("Cookie", "TWFID="+twfid)
	req.Header.Set("Content-Type", "text/html; charset=utf-8")

	resp, err := c.Do(req)
	if err != nil {
		log.Print(err)
		log.Printf("Cannot request %s \n", path)
		return "", false
	}

	var buf bytes.Buffer
	io.Copy(&buf, resp.Body)
	defer func(Body io.ReadCloser) {
		err0 := Body.Close()
		if err0 != nil {
		}
	}(resp.Body)

	//    log.Printf("%s \n", string(buf[:]))

	err = xml.Unmarshal(buf.Bytes(), &in)
	if err != nil {
		log.Print(err)
		log.Printf("Cannot parse %s \n", path)

		return buf.String(), false
	} else {
		log.Printf("Parsed %s \n", path)

		return buf.String(), true
	}

}
