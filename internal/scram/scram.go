// mgo - MongoDB driver for Go
//
// Copyright (c) 2014 - Gustavo Niemeyer <gustavo@niemeyer.net>
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package scram implements a SCRAM-{SHA-1,etc} client per RFC5802.
//
// http://tools.ietf.org/html/rfc5802
//
package scram

import (
	"bytes"
	"errors"

	xdg "github.com/xdg-go/scram"
)

// Client adapts a SCRAM client (SCRAM-SHA-1, SCRAM-SHA-256).
//
// A Client may be used within a SASL conversation with logic resembling:
//
//    mechanism, err := scram.NewMethod("SCRAM-SHA-256")
//
//    if err != nil {
//      log.Fatal(err)
//    }
//
//    var in []byte
//    var client = scram.NewClient(, user, pass)
//    for client.Step(in) {
//            out := client.Out()
//            // send out to server
//            in := serverOut
//    }
//    if client.Err() != nil {
//            // auth failed
//    }
//
type Client struct {
	out  bytes.Buffer
	err  error
	conv *xdg.ClientConversation
}

// Method defines the variant of SCRAM to use
type Method struct {
	method string
}

const (
	// ScramSha1 use the SCRAM-SHA-1 variant
	ScramSha1 = "SCRAM-SHA-1"

	// ScramSha256 use the SCRAM-SHA-256 variant
	ScramSha256 = "SCRAM-SHA-256"
)

// NewMethod returns a Method if the input method string is supported
// otherwise it returns an error.
// Supported method strings:
// - "SCRAM-SHA-1"
// - "SCRAM-SHA-256"
func NewMethod(methodString string) (*Method, error) {
	switch methodString {
	case ScramSha1, ScramSha256:
		return &Method{method: methodString}, nil
	default:
		return nil, errors.New("invalid SCRAM mechanism")
	}
}

// NewClient returns a new SCRAM client with the provided hash algorithm.
//
// For SCRAM-SHA-1, for example, use:
//
//    method, _ := scram.NewMethod("SCRAM-SHA-1")
//
//    client := scram.NewClient(method, user, pass)
//
func NewClient(method *Method, user, pass string) *Client {
	var client *xdg.Client
	var err error

	switch method.method {
	case ScramSha1:
		client, err = xdg.SHA1.NewClient(user, pass, "")
	case ScramSha256:
		client, err = xdg.SHA256.NewClient(user, pass, "")
	}

	c := &Client{
		conv: client.NewConversation(),
		err:  err,
	}
	c.out.Grow(256)
	return c
}

// Out returns the data to be sent to the server in the current step.
func (c *Client) Out() []byte {
	if c.out.Len() == 0 {
		return []byte{}
	}
	return c.out.Bytes()
}

// Err returns the error that occurred, or nil if there were no errors.
func (c *Client) Err() error {
	return c.err
}

// Step processes the incoming data from the server and makes the
// next round of data for the server available via Client.Out.
// Step returns false if there are no errors and more data is
// still expected.
func (c *Client) Step(in []byte) bool {
	var resp string
	c.out.Reset()
	resp, c.err = c.conv.Step(string(in))
	_, c.err = c.out.Write([]byte(resp))
	return c.conv.Valid() || c.err != nil
}
