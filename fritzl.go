package main

import (
	"crypto/tls"
	"net/http"
	"crypto/md5"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"unicode/utf16"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
)

var (
    device      string = "en0"
    snapshotLen int32  = 1024
    promiscuous bool   = false
    err         error
    timeout     time.Duration = -1 * time.Second
    handle      *pcap.Handle
)


func utf16leMd5(s string) [16]byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, len(codes)*2)
	for i, r := range codes {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return md5.Sum(b)
}

type SessionInfo struct {
	XMLName   xml.Name `xml:"SessionInfo"`
	Challenge string   `xml:"Challenge"`
	SID       string   `xml:"SID"`
}

func GetChallenge(c *http.Client) string {
	res, err := c.Get("https://fritz.box/login_sid.lua")
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	sessionInfo := SessionInfo{}
	xmlData, ioerr := ioutil.ReadAll(res.Body)
	if ioerr != nil {
		log.Fatal(ioerr)
	}
	xml.Unmarshal(xmlData, &sessionInfo)
	return sessionInfo.Challenge
}

func GetSID(c *http.Client, username string, password string, challenge string) string {
	sessionInfo := SessionInfo{}
	toBeMd5ed := fmt.Sprintf("%s-%s", challenge, password)
	md5edShit := utf16leMd5(toBeMd5ed)
	response := fmt.Sprintf("%s-%x", challenge, md5edShit)
	connectURL := fmt.Sprintf("https://fritz.box/login_sid.lua?username=%s&response=%s", username, response)
	res, err := c.Get(connectURL)
	if err != nil {
		log.Fatal(err)
	}
	xmlData, err := ioutil.ReadAll(res.Body)
	fmt.Println(string(xmlData))
	xml.Unmarshal(xmlData, &sessionInfo)
	return sessionInfo.SID
}

func ToggleCoffee(c *http.Client, sid string) {
	ain := "087610206222"
	res, err := c.Get(fmt.Sprintf("https://fritz.box/webservices/homeautoswitch.lua?ain=%s&switchcmd=setswitchtoggle&sid=%s", ain, sid))
	if err != nil {
		log.Fatal(err)
	}
	xmlData, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(xmlData))
}

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()

	filter := "ether src ac:63:be:ef:6c:57 and arp"
	err = handle.SetBPFFilter(filter)
	if err != nil { log.Fatal(err) }

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	username := ""
	password := ""

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for range packetSource.Packets() {
		challenge := GetChallenge(client)
		sid := GetSID(client, username, password, challenge)
		ToggleCoffee(client, sid)
	}

}
