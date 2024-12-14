// Package xid is a globally unique id generator suited for web scale
//
// Xid is using Mongo Object ID algorithm to generate globally unique ids:
// https://docs.mongodb.org/manual/reference/object-id/
//
//   - 4-byte value representing the seconds since the Unix epoch,
//   - 3-byte machine identifier,
//   - 2-byte process id, and
//   - 3-byte counter, starting with a random value.
//
// The binary representation of the id is compatible with Mongo 12 bytes Object IDs.
// The string representation is using base32 hex (w/o padding) for better space efficiency
// when stored in that form (20 bytes). The hex variant of base32 is used to retain the
// sortable property of the id.
//
// Xid doesn't use base64 because case sensitivity and the 2 non alphanum chars may be an
// issue when transported as a string between various systems. Base36 wasn't retained either
// because 1/ it's not standard 2/ the resulting size is not predictable (not bit aligned)
// and 3/ it would not remain sortable. To validate a base32 `xid`, expect a 20 chars long,
// all lowercase sequence of `a` to `v` letters and `0` to `9` numbers (`[0-9a-v]{20}`).
//
// UUID is 16 bytes (128 bits), snowflake is 8 bytes (64 bits), xid stands in between
// with 12 bytes with a more compact string representation ready for the web and no
// required configuration or central generation server.
//
// Features:
//
//   - Size: 12 bytes (96 bits), smaller than UUID, larger than snowflake
//   - Base32 hex encoded by default (16 bytes storage when transported as printable string)
//   - Non configured, you don't need set a unique machine and/or data center id
//   - K-ordered
//   - Embedded time with 1 second precision
//   - Unicity guaranteed for 16,777,216 (24 bits) unique ids per second and per host/process
//
// Best used with xlog's RequestIDHandler (https://godoc.org/github.com/rs/xlog#RequestIDHandler).
//
// References:
//
//   - http://www.slideshare.net/davegardnerisme/unique-id-generation-in-distributed-systems
//   - https://en.wikipedia.org/wiki/Universally_unique_identifier
//   - https://blog.twitter.com/2010/announcing-snowflake
package xid

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"database/sql/driver"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"sort"
	"sync/atomic"
	"time"
	"unsafe"
)

// ID represents a unique request id
type ID [rawLen]byte

const (
	encodedLen = 20 // string encoded len
	rawLen     = 12 // binary raw len
)

var (
	// ErrInvalidID is returned when trying to unmarshal an invalid ID
	ErrInvalidID = errors.New("xid: invalid ID")
	// objectIDCounter is atomically incremented when generating a new ObjectId using NewObjectId() function. It's used as a counter part of an id. This id is initialized with a random value.
	objectIDCounter = randInt()
	// machineId stores machine id generated once and used in subsequent calls to NewObjectId function.
	machineID = readMachineID()
	// pid stores the current process id
	pid = os.Getpid()
	// a zero id constant
	nilID ID
	// the base32 encoder we use; we use the extended-hex variant with no padding
	encoder = base32.HexEncoding.WithPadding(-1)
	// default generator
	dgen = NewGenerator(Sequential)
)

type Mode int

const (
	Sequential Mode = iota
	Distributed
)

func init() {
	// If /proc/self/cpuset exists and is not /, we can assume that we are in a form
	// of container and use the content of cpuset xor-ed with the PID in order get a
	// reasonable machine global unique PID.
	b, err := ioutil.ReadFile("/proc/self/cpuset")
	if err == nil && len(b) > 1 {
		pid ^= int(crc32.ChecksumIEEE(b))
	}
}

// machineId generates machine id and puts it into the machineId global variable. If
// this function fails to get the hostname, it will cause a runtime error.
func readMachineID() []byte {
	id := make([]byte, 3)
	hid, err := readPlatformMachineID()
	if err != nil || len(hid) == 0 {
		hid, err = os.Hostname()
	}
	if err == nil && len(hid) != 0 {
		hw := md5.New()
		hw.Write([]byte(hid))
		copy(id, hw.Sum(nil))
	} else {
		// Fallback to rand number if machine id can't be gathered
		if _, randErr := rand.Reader.Read(id); randErr != nil {
			panic(fmt.Errorf("xid: cannot get hostname nor generate a random number: %v; %v", err, randErr))
		}
	}
	return id
}

// randInt generates a random uint32
func randInt() uint32 {
	b := make([]byte, 3)
	if _, err := rand.Reader.Read(b); err != nil {
		panic(fmt.Errorf("xid: cannot generate random number: %v;", err))
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

type Generator struct {
	mode Mode
}

func NewGenerator(m Mode) *Generator {
	return &Generator{
		mode: m,
	}
}

// New generates a globally unique ID
func (g *Generator) New() ID {
	return g.NewWithTime(time.Now())
}

// NewWithTime generates a globally unique ID with the passed in time
func (g *Generator) NewWithTime(t time.Time) ID {
	var id ID
	// Increment our counter
	ctr := atomic.AddUint32(&objectIDCounter, 1)
	if g.mode == Sequential {
		// Timestamp, 4 bytes, big endian
		binary.BigEndian.PutUint32(id[:], uint32(t.Unix()))
		// Machine, first 3 bytes of md5(hostname)
		id[4] = machineID[0]
		id[5] = machineID[1]
		id[6] = machineID[2]
		// PID, 2 bytes, specs don't specify endianness, but we use big endian.
		id[7] = byte(pid >> 8)
		id[8] = byte(pid)
		// Counter, 3 bytes, big endian
		id[9] = byte(ctr >> 16)
		id[10] = byte(ctr >> 8)
		id[11] = byte(ctr)
	} else {
		// Counter, 3 bytes, little endian
		id[0] = byte(ctr)
		id[1] = byte(ctr >> 8)
		id[2] = byte(ctr >> 16)
		// Machine, first 3 bytes of md5(hostname)
		id[3] = machineID[0]
		id[4] = machineID[1]
		id[5] = machineID[2]
		// PID, 2 bytes, specs don't specify endianness, but we use big endian.
		id[6] = byte(pid >> 8)
		id[7] = byte(pid)
		// Timestamp, 4 bytes, big endian
		binary.BigEndian.PutUint32(id[8:], uint32(t.Unix()))
	}
	return id
}

// FromString reads an ID from its string representation
func (g *Generator) FromString(t string) (ID, error) {
	if len(t) != encodedLen {
		return nilID, ErrInvalidID
	}
	var id ID
	decode(&id, []byte(t))
	return id, nil
}

// FromBytes convert the byte array representation of `ID` back to `ID`
func (g *Generator) FromBytes(b []byte) (ID, error) {
	if len(b) != rawLen {
		return nilID, ErrInvalidID
	}
	var id ID
	copy(id[:], b)
	return id, nil
}

// Time returns the timestamp part of the id. It's a runtime error to call this method with an invalid id.
func (g *Generator) Time(id ID) time.Time {
	var secs int64
	if g.mode == Sequential {
		secs = int64(binary.BigEndian.Uint32(id[0:4]))
	} else {
		secs = int64(binary.BigEndian.Uint32(id[8:]))
	}
	return time.Unix(secs, 0)
}

// Machine returns the 3-byte machine id part of the id. It's a runtime error to call this method with an invalid id.
func (g *Generator) Machine(id ID) []byte {
	if g.mode == Sequential {
		return id[4:7]
	} else {
		return id[3:6]
	}
}

// PID returns the process id part of the id. It's a runtime error to call this method with an invalid id.
func (g *Generator) PID(id ID) uint16 {
	if g.mode == Sequential {
		return binary.BigEndian.Uint16(id[7:9])
	} else {
		return binary.BigEndian.Uint16(id[6:8])
	}
}

// Counter returns the incrementing value part of the id. It's a runtime error to call this method with an invalid id.
func (g *Generator) Counter(id ID) int32 {
	var b []byte
	if g.mode == Sequential {
		b = id[9:12]
		return int32(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])) // Counter is stored as big-endian 3-byte value
	} else {
		b = id[0:3]
		return int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16) // Counter is stored as little-endian 3-byte value
	}
}

// New generates a globally unique ID
func New() ID {
	return dgen.New()
}

// NewWithTime generates a globally unique ID with the passed in time
func NewWithTime(t time.Time) ID {
	return dgen.NewWithTime(t)
}

// FromString reads an ID from its string representation
func FromString(id string) (ID, error) {
	return dgen.FromString(id)
}

// FromBytes reads an ID from its string representation
func FromBytes(id []byte) (ID, error) {
	return dgen.FromBytes(id)
}

// Time returns the timestamp part of the id. It's a runtime error to call this method with an invalid id.
func Time(id ID) time.Time {
	return dgen.Time(id)
}

// Machine returns the 3-byte machine id part of the id. It's a runtime error to call this method with an invalid id.
func Machine(id ID) []byte {
	return dgen.Machine(id)
}

// PID returns the process id part of the id. It's a runtime error to call this method with an invalid id.
func PID(id ID) uint16 {
	return dgen.PID(id)
}

// Counter returns the incrementing value part of the id. It's a runtime error to call this method with an invalid id.
func Counter(id ID) int32 {
	return dgen.Counter(id)
}

// String returns a 20-byte string representation
func (id ID) String() string {
	text := make([]byte, encodedLen)
	encode(text, id[:])
	return *(*string)(unsafe.Pointer(&text))
}

// Encode encodes the id using base32 encoding, writing 20 bytes to dst and return it.
func (id ID) Encode(dst []byte) []byte {
	encode(dst, id[:])
	return dst
}

// MarshalText implements encoding/text TextMarshaler interface
func (id ID) MarshalText() ([]byte, error) {
	text := make([]byte, encodedLen)
	encode(text, id[:])
	return text, nil
}

// MarshalJSON implements encoding/json Marshaler interface
func (id ID) MarshalJSON() ([]byte, error) {
	if id.IsZero() {
		return []byte("null"), nil
	}
	text := make([]byte, encodedLen+2)
	encode(text[1:encodedLen+1], id[:])
	text[0], text[encodedLen+1] = '"', '"'
	return text, nil
}

// encode via the stdlib base32 package
func encode(dst, id []byte) {
	encoder.Encode(dst, id)
}

// UnmarshalText implements encoding/text TextUnmarshaler interface
func (id *ID) UnmarshalText(text []byte) error {
	if len(text) != encodedLen {
		return ErrInvalidID
	}
	decode(id, text)
	return nil
}

// UnmarshalJSON implements encoding/json Unmarshaler interface, which specifically
// allows for the literal 'null' to represent the zero value.
func (id *ID) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*id = nilID
		return nil
	}
	// empty string '""' is the smallest possible processable input since are being
	// (maybe unnecessarily) clever here and avoiding more expensive string parsing
	// in encoding/json
	if len(b) < 2 {
		return ErrInvalidID
	}
	return id.UnmarshalText(b[1 : len(b)-1])
}

// decode by unrolling the stdlib base32 algorithm + removing all safe checks
func decode(id *ID, src []byte) {
	encoder.Decode(id[:], src)
}

// Value implements the driver.Valuer interface.
func (id ID) Value() (driver.Value, error) {
	if id.IsZero() {
		return nil, nil
	}
	b, err := id.MarshalText()
	return string(b), err
}

// Scan implements the sql.Scanner interface.
func (id *ID) Scan(value interface{}) (err error) {
	switch val := value.(type) {
	case string:
		return id.UnmarshalText([]byte(val))
	case []byte:
		return id.UnmarshalText(val)
	case nil:
		*id = nilID
		return nil
	default:
		return fmt.Errorf("xid: scanning unsupported type: %T", value)
	}
}

// IsZero Returns true if this is a "nil" ID
func (id ID) IsZero() bool {
	return id == nilID
}

// NilID returns a zero value for `xid.ID`.
func Zero() ID {
	return nilID
}

// Bytes returns the byte array representation of `ID`
func (id ID) Bytes() []byte {
	return id[:]
}

// Compare returns an integer comparing two IDs. It behaves just like `bytes.Compare`.
// The result will be 0 if two IDs are identical, -1 if current id is less than the other one,
// and 1 if current id is greater than the other.
func (id ID) Compare(other ID) int {
	return bytes.Compare(id[:], other[:])
}

type sorter []ID

func (s sorter) Len() int {
	return len(s)
}

func (s sorter) Less(i, j int) bool {
	return s[i].Compare(s[j]) < 0
}

func (s sorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Sort sorts an array of IDs inplace. It works by wrapping `[]ID` and use `sort.Sort`.
func Sort(ids []ID) {
	sort.Sort(sorter(ids))
}
