package quic

import (
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const num = 100000

func runServer(conn net.PacketConn) ([]uint64, error) {
	b := make([]byte, 1024)
	pns := make([]uint64, num)
	for i := 0; i < num; i++ {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		b = b[:1024]
		n, _, err := conn.ReadFrom(b)
		if err != nil {
			return nil, err
		}
		b = b[:n]
		pns[i] = binary.BigEndian.Uint64(b[:8])
	}
	return pns, nil
}

func runClient(addr *net.UDPAddr) error {
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	b := make([]byte, 1024)
	for i := 0; i < num; i++ {
		b = b[:8+mrand.Intn(1000)]
		binary.BigEndian.PutUint64(b[:8], uint64(i))
		_, err := conn.Write(b)
		if err != nil {
			return err
		}
	}
	return nil
}

var _ = FDescribe("Reordering", func() {
	It("sends", func() {
		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		ln, err := net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		pnChan := make(chan []uint64)
		go func() {
			defer GinkgoRecover()
			defer close(pnChan)
			pns, _ := runServer(ln)
			pnChan <- pns
		}()

		time.Sleep(100 * time.Millisecond)
		Expect(runClient(ln.LocalAddr().(*net.UDPAddr))).To(Succeed())
		pns := <-pnChan
		if len(pns) != num {
			Skip(fmt.Sprintf("didn't receive enough packtes: %d. weird.", len(pns)))
		}

		fmt.Println(len(pns))

		sorted := true
		var diff uint64
		for i := uint64(0); i < num; i++ {
			pn := pns[i]
			if pn != i {
				sorted = false
				if pn > i {
					diff += pn - i
				} else {
					diff += i - pn
				}
			}
		}
		if !sorted {
			fmt.Printf("unsorted: %x\n", pns)
			fmt.Println("diff:", diff)
		}
		Expect(sorted).To(BeTrue())
	})
})
