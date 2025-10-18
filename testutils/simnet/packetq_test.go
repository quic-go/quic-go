package simnet

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketQueue_Basic(t *testing.T) {
	q := newPacketQ(1000)

	// Test adding and removing single packet
	testPacket := packetWithDeliveryTime{Packet: Packet{Data: []byte("test packet")}, DeliveryTime: time.Now()}
	q.Push(testPacket)

	got, ok := q.Pop()
	if !ok {
		t.Error("Expected successful Pop, got not ok")
	}
	if !bytes.Equal(got.Data, testPacket.Data) {
		t.Errorf("Expected packet %v, got %v", testPacket, got)
	}
}

func TestPacketQueue_Order(t *testing.T) {
	q := newPacketQ(1000)

	packets := []packetWithDeliveryTime{
		{Packet: Packet{Data: []byte("first")}, DeliveryTime: time.Now()},
		{Packet: Packet{Data: []byte("second")}, DeliveryTime: time.Now()},
		{Packet: Packet{Data: []byte("third")}, DeliveryTime: time.Now()},
	}

	for _, p := range packets {
		q.Push(p)
	}

	for i, want := range packets {
		got, ok := q.Pop()
		if !ok {
			t.Errorf("Pop %d: expected success, got not ok", i)
			continue
		}
		if !bytes.Equal(got.Data, want.Data) {
			t.Errorf("Pop %d: expected %v, got %v", i, want, got)
		}
	}
}

func TestPacketQueue_BlockedThenClose(t *testing.T) {
	q := newPacketQ(1000)

	go func() {
		time.Sleep(10 * time.Millisecond)
		q.Close()
	}()

	startTime := time.Now()

	// Test Pop on empty queue
	_, ok := q.Pop()
	if ok {
		t.Error("Expected closed queue")
	}

	dur := time.Since(startTime)
	if dur < 10*time.Millisecond {
		t.Errorf("Expected Pop to block for at least 10ms, got %v", dur)
	}
}

func TestPacketQueue_Blocking(t *testing.T) {
	q := newPacketQ(1000)
	done := make(chan bool)
	timeout := time.After(100 * time.Millisecond)

	testPacket := Packet{Data: []byte("test packet")}

	var readPacket atomic.Bool
	// Start consumer before pushing any data
	go func() {
		packet, ok := q.Pop()
		if !ok {
			t.Error("Expected successful Pop, got not ok")
			done <- true
			return
		}
		readPacket.Store(true)
		if !bytes.Equal(packet.Data, testPacket.Data) {
			t.Errorf("Expected %v, got %v", testPacket, packet)
		}
		done <- true
	}()

	// Wait a bit to ensure consumer is blocked
	time.Sleep(10 * time.Millisecond)
	if readPacket.Load() {
		t.Error("Consumer should not have read packet")
	}

	// Push data that should unblock consumer
	q.Push(packetWithDeliveryTime{Packet: testPacket, DeliveryTime: time.Now()})

	select {
	case <-done:
		// Success - consumer received the packet
	case <-timeout:
		t.Error("Test timed out - Pop did not unblock after Push")
	}
	if !readPacket.Load() {
		t.Error("Consumer should have read packet")
	}
}

func TestPacketQueue_Concurrent(t *testing.T) {
	q := newPacketQ(1000)
	done := make(chan bool)

	// Start producer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			q.Push(packetWithDeliveryTime{Packet: Packet{Data: []byte{byte(i)}}, DeliveryTime: time.Now()})
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	// Start consumer goroutine
	go func() {
		count := 0
		for count < 100 {
			_, ok := q.Pop()
			if ok {
				count++
			}
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	// Wait for both goroutines to finish
	<-done
	<-done
}
