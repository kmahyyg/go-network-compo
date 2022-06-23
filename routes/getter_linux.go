//go:build linux

package routes

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"strings"
)

const (
	ROUTE_FILE_PATH     = "/proc/net/route"
	seperator           = "\t" // not rune, but string here
	totalFields         = 11
	ROUTE_FILE_PATH_DBG = "/Users/kmahyyg/Downloads/route.bin"
)

func Retrieve() ([]NetRoute, error) {
	// read file in a total, without race condition
	fileData, err := ioutil.ReadFile(ROUTE_FILE_PATH_DBG)
	if err != nil {
		return nil, err
	}
	// scan line by line
	scanner := bufio.NewScanner(bytes.NewBuffer(fileData))
	firstLineSkipped := false
	for scanner.Scan() {
		// process end of file
		if scanner.Err() == io.EOF {
			break
		}

		// other errors
		if err = scanner.Err(); err != nil {
			log.Println(err)
		}
		// skip table header
		if !firstLineSkipped {
			if !scanner.Scan() {
				// ignore first line
				return nil, errors.New("invalid route file")
			}
			firstLineSkipped = true
			continue
		}
		// go ahead
		routeRow := strings.Split(scanner.Text(), seperator)
		if len(routeRow) != totalFields {
			return nil, errors.New("invalid route row")
		}

	}
	// debug placeholder
	return nil, nil
}
