// 物理硬件标识
package pkey

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var key []byte

var (
	ErrInit = errors.New("pkey: 初始化失败")
)

func init() {
	path, err := filepath.Abs(os.Args[0])
	if err != nil {
		log.Fatal(ErrInit)
	}

	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		log.Fatal(ErrInit)
	}
	getVolumeInfo, err := syscall.GetProcAddress(kernel32, "GetVolumeInformationW")
	if err != nil {
		log.Fatal(ErrInit)
	}

	serial, mcl, flags := uint32(0), uint32(0), uint32(0)
	ret, _, _ := syscall.Syscall9(uintptr(getVolumeInfo),
		8,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(filepath.VolumeName(path)+`\`))),
		uintptr(unsafe.Pointer(&(make([]uint16, syscall.MAX_PATH+1))[0])),
		uintptr(uint32(syscall.MAX_PATH+1)),
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&mcl)),
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&(make([]uint16, syscall.MAX_PATH+1))[0])),
		uintptr(uint32(syscall.MAX_PATH+1)),
		0)
	if ret == 0 {
		log.Fatal(ErrInit)
	}

	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, serial)

	hs := sha256.New()
	if _, err := hs.Write(bs); err != nil {
		log.Fatal(ErrInit)
	}
	key = hs.Sum(nil)
}

// 返回物理硬件标识
func Get() []byte {
	x := make([]byte, len(key))
	copy(x, key)
	return x
}
