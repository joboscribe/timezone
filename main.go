package timezone

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
)

//go:generate env ZONEINFO=$GOROOT/lib/time/zoneinfo.zip go run genzabbrs.go -output zoneinfo_abbrs_windows.go

// A Location maps time instants to the zone in use at that time.
// Typically, the Location represents the collection of time offsets
// in use in a geographical area, such as CEST and CET for central Europe.
type Location struct {
	name string
	zone []zone
	tx   []zoneTrans

	// Most lookups will be for the current time.
	// To avoid the binary search through tx, keep a
	// static one-element cache that gives the correct
	// zone for the time when the Location was created.
	// if cacheStart <= t < cacheEnd,
	// lookup can return cacheZone.
	// The units for cacheStart and cacheEnd are seconds
	// since January 1, 1970 UTC, to match the argument
	// to lookup.
	cacheStart int64
	cacheEnd   int64
	cacheZone  *zone
}

// A zone represents a single time zone such as CEST or CET.
type zone struct {
	name   string // abbreviated name, "CET"
	offset int    // seconds east of UTC
	isDST  bool   // is this zone Daylight Savings Time?
}

func (z zone) Name() string {
	return z.name
}

func (z zone) Offset() int {
	return z.offset
}

func (z zone) IsDST() bool {
	return z.isDST
}

// A zoneTrans represents a single time zone transition.
type zoneTrans struct {
	when         int64 // transition time, in seconds since 1970 GMT
	index        uint8 // the index of the zone that goes into effect at that time
	isstd, isutc bool  // ignored - no idea what these mean
}

func (z zoneTrans) When() int64 {
	return z.when
}

func (z zoneTrans) Index() uint8 {
	return z.index
}

// alpha and omega are the beginning and end of time for zone
// transitions.
const (
	alpha = -1 << 63  // math.MinInt64
	omega = 1<<63 - 1 // math.MaxInt64
)

// UTC represents Universal Coordinated Time (UTC).
var UTC *Location = &utcLoc

// utcLoc is separate so that get can refer to &utcLoc
// and ensure that it never returns a nil *Location,
// even if a badly behaved client has changed UTC.
var utcLoc = Location{name: "UTC"}

// Local represents the system's local time zone.
var Local *Location = &localLoc

// localLoc is separate so that initLocal can initialize
// it even if a client has changed Local.
var localLoc Location
var localOnce sync.Once

func (l *Location) get() *Location {
	if l == nil {
		return &utcLoc
	}
	if l == &localLoc {
		localOnce.Do(initLocal)
	}
	return l
}

// String returns a descriptive name for the time zone information,
// corresponding to the name argument to LoadLocation or FixedZone.
func (l *Location) String() string {
	r := bytes.NewBuffer(make([]byte, 0))
	fmt.Fprintf(r, "tx: %#v", l.tx)
	return l.get().name + r.String()
}

func (l *Location) GetZones() []zone {
	return l.zone
}

func (l *Location) GetZoneTrans() []zoneTrans {
	return l.tx
}

// FixedZone returns a Location that always uses
// the given zone name and offset (seconds east of UTC).
func FixedZone(name string, offset int) *Location {
	l := &Location{
		name:       name,
		zone:       []zone{{name, offset, false}},
		tx:         []zoneTrans{{alpha, 0, false, false}},
		cacheStart: alpha,
		cacheEnd:   omega,
	}
	l.cacheZone = &l.zone[0]
	return l
}

// lookup returns information about the time zone in use at an
// instant in time expressed as seconds since January 1, 1970 00:00:00 UTC.
//
// The returned information gives the name of the zone (such as "CET"),
// the start and end times bracketing sec when that zone is in effect,
// the offset in seconds east of UTC (such as -5*60*60), and whether
// the daylight savings is being observed at that time.
func (l *Location) lookup(sec int64) (name string, offset int, isDST bool, start, end int64) {
	l = l.get()

	if len(l.zone) == 0 {
		name = "UTC"
		offset = 0
		isDST = false
		start = alpha
		end = omega
		return
	}

	if zone := l.cacheZone; zone != nil && l.cacheStart <= sec && sec < l.cacheEnd {
		name = zone.name
		offset = zone.offset
		isDST = zone.isDST
		start = l.cacheStart
		end = l.cacheEnd
		return
	}

	if len(l.tx) == 0 || sec < l.tx[0].when {
		zone := &l.zone[l.lookupFirstZone()]
		name = zone.name
		offset = zone.offset
		isDST = zone.isDST
		start = alpha
		if len(l.tx) > 0 {
			end = l.tx[0].when
		} else {
			end = omega
		}
		return
	}

	// Binary search for entry with largest time <= sec.
	// Not using sort.Search to avoid dependencies.
	tx := l.tx
	end = omega
	lo := 0
	hi := len(tx)
	for hi-lo > 1 {
		m := lo + (hi-lo)/2
		lim := tx[m].when
		if sec < lim {
			end = lim
			hi = m
		} else {
			lo = m
		}
	}
	zone := &l.zone[tx[lo].index]
	name = zone.name
	offset = zone.offset
	isDST = zone.isDST
	start = tx[lo].when
	// end = maintained during the search
	return
}

// lookupFirstZone returns the index of the time zone to use for times
// before the first transition time, or when there are no transition
// times.
//
// The reference implementation in localtime.c from
// http://www.iana.org/time-zones/repository/releases/tzcode2013g.tar.gz
// implements the following algorithm for these cases:
// 1) If the first zone is unused by the transitions, use it.
// 2) Otherwise, if there are transition times, and the first
//    transition is to a zone in daylight time, find the first
//    non-daylight-time zone before and closest to the first transition
//    zone.
// 3) Otherwise, use the first zone that is not daylight time, if
//    there is one.
// 4) Otherwise, use the first zone.
func (l *Location) lookupFirstZone() int {
	// Case 1.
	if !l.firstZoneUsed() {
		return 0
	}

	// Case 2.
	if len(l.tx) > 0 && l.zone[l.tx[0].index].isDST {
		for zi := int(l.tx[0].index) - 1; zi >= 0; zi-- {
			if !l.zone[zi].isDST {
				return zi
			}
		}
	}

	// Case 3.
	for zi := range l.zone {
		if !l.zone[zi].isDST {
			return zi
		}
	}

	// Case 4.
	return 0
}

// firstZoneUsed returns whether the first zone is used by some
// transition.
func (l *Location) firstZoneUsed() bool {
	for _, tx := range l.tx {
		if tx.index == 0 {
			return true
		}
	}
	return false
}

// lookupName returns information about the time zone with
// the given name (such as "EST") at the given pseudo-Unix time
// (what the given time of day would be in UTC).
func (l *Location) lookupName(name string, unix int64) (offset int, isDST bool, ok bool) {
	l = l.get()

	// First try for a zone with the right name that was actually
	// in effect at the given time. (In Sydney, Australia, both standard
	// and daylight-savings time are abbreviated "EST". Using the
	// offset helps us pick the right one for the given time.
	// It's not perfect: during the backward transition we might pick
	// either one.)
	for i := range l.zone {
		zone := &l.zone[i]
		if zone.name == name {
			nam, offset, isDST, _, _ := l.lookup(unix - int64(zone.offset))
			if nam == zone.name {
				return offset, isDST, true
			}
		}
	}

	// Otherwise fall back to an ordinary name match.
	for i := range l.zone {
		zone := &l.zone[i]
		if zone.name == name {
			return zone.offset, zone.isDST, true
		}
	}

	// Otherwise, give up.
	return
}

// NOTE(rsc): Eventually we will need to accept the POSIX TZ environment
// syntax too, but I don't feel like implementing it today.

var errLocation = errors.New("time: invalid location name")

var zoneinfo *string
var zoneinfoOnce sync.Once

// LoadLocation returns the Location with the given name.
//
// If the name is "" or "UTC", LoadLocation returns UTC.
// If the name is "Local", LoadLocation returns Local.
//
// Otherwise, the name is taken to be a location name corresponding to a file
// in the IANA Time Zone database, such as "America/New_York".
//
// The time zone database needed by LoadLocation may not be
// present on all systems, especially non-Unix systems.
// LoadLocation looks in the directory or uncompressed zip file
// named by the ZONEINFO environment variable, if any, then looks in
// known installation locations on Unix systems,
// and finally looks in $GOROOT/lib/time/zoneinfo.zip.
func LoadLocation(name string) (*Location, error) {
	if name == "" || name == "UTC" {
		return UTC, nil
	}
	if name == "Local" {
		return Local, nil
	}
	if containsDotDot(name) || name[0] == '/' || name[0] == '\\' {
		// No valid IANA Time Zone name contains a single dot,
		// much less dot dot. Likewise, none begin with a slash.
		return nil, errLocation
	}
	zoneinfoOnce.Do(func() {
		env, _ := syscall.Getenv("ZONEINFO")
		zoneinfo = &env
	})
	if zoneinfo != nil && *zoneinfo != "" {
		if z, err := loadZoneFile(*zoneinfo, name); err == nil {
			z.name = name
			return z, nil
		}
	}
	return loadLocation(name)
}

// containsDotDot reports whether s contains "..".
func containsDotDot(s string) bool {
	if len(s) < 2 {
		return false
	}
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '.' && s[i+1] == '.' {
			return true
		}
	}
	return false
}

// maxFileSize is the max permitted size of files read by readFile.
// As reference, the zoneinfo.zip distributed by Go is ~350 KB,
// so 10MB is overkill.
const maxFileSize = 10 << 20

type fileSizeError string

func (f fileSizeError) Error() string {
	return "time: file " + string(f) + " is too large"
}

// Copies of io.Seek* constants to avoid importing "io":
const (
	seekStart   = 0
	seekCurrent = 1
	seekEnd     = 2
)

// Simple I/O interface to binary blob of data.
type data struct {
	p     []byte
	error bool
}

func (d *data) read(n int) []byte {
	if len(d.p) < n {
		d.p = nil
		d.error = true
		return nil
	}
	p := d.p[0:n]
	d.p = d.p[n:]
	return p
}

func (d *data) big4() (n uint32, ok bool) {
	p := d.read(4)
	if len(p) < 4 {
		d.error = true
		return 0, false
	}
	return uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3]), true
}

func (d *data) byte() (n byte, ok bool) {
	p := d.read(1)
	if len(p) < 1 {
		d.error = true
		return 0, false
	}
	return p[0], true
}

// Make a string by stopping at the first NUL
func byteString(p []byte) string {
	for i := 0; i < len(p); i++ {
		if p[i] == 0 {
			return string(p[0:i])
		}
	}
	return string(p)
}

var badData = errors.New("malformed time zone information")

func loadZoneData(bytes []byte) (l *Location, err error) {
	d := data{bytes, false}

	// 4-byte magic "TZif"
	if magic := d.read(4); string(magic) != "TZif" {
		return nil, badData
	}

	// 1-byte version, then 15 bytes of padding
	var p []byte
	if p = d.read(16); len(p) != 16 || p[0] != 0 && p[0] != '2' && p[0] != '3' {
		return nil, badData
	}

	// six big-endian 32-bit integers:
	//	number of UTC/local indicators
	//	number of standard/wall indicators
	//	number of leap seconds
	//	number of transition times
	//	number of local time zones
	//	number of characters of time zone abbrev strings
	const (
		NUTCLocal = iota
		NStdWall
		NLeap
		NTime
		NZone
		NChar
	)
	var n [6]int
	for i := 0; i < 6; i++ {
		nn, ok := d.big4()
		if !ok {
			return nil, badData
		}
		n[i] = int(nn)
	}

	// Transition times.
	txtimes := data{d.read(n[NTime] * 4), false}

	// Time zone indices for transition times.
	txzones := d.read(n[NTime])

	// Zone info structures
	zonedata := data{d.read(n[NZone] * 6), false}

	// Time zone abbreviations.
	abbrev := d.read(n[NChar])

	// Leap-second time pairs
	d.read(n[NLeap] * 8)

	// Whether tx times associated with local time types
	// are specified as standard time or wall time.
	isstd := d.read(n[NStdWall])

	// Whether tx times associated with local time types
	// are specified as UTC or local time.
	isutc := d.read(n[NUTCLocal])

	if d.error { // ran out of data
		return nil, badData
	}

	// If version == 2 or 3, the entire file repeats, this time using
	// 8-byte ints for txtimes and leap seconds.
	// We won't need those until 2106.

	// Now we can build up a useful data structure.
	// First the zone information.
	//	utcoff[4] isdst[1] nameindex[1]
	zone := make([]zone, n[NZone])
	for i := range zone {
		var ok bool
		var n uint32
		if n, ok = zonedata.big4(); !ok {
			return nil, badData
		}
		zone[i].offset = int(int32(n))
		var b byte
		if b, ok = zonedata.byte(); !ok {
			return nil, badData
		}
		zone[i].isDST = b != 0
		if b, ok = zonedata.byte(); !ok || int(b) >= len(abbrev) {
			return nil, badData
		}
		zone[i].name = byteString(abbrev[b:])
	}

	// Now the transition time info.
	tx := make([]zoneTrans, n[NTime])
	for i := range tx {
		var ok bool
		var n uint32
		if n, ok = txtimes.big4(); !ok {
			return nil, badData
		}
		tx[i].when = int64(int32(n))
		if int(txzones[i]) >= len(zone) {
			return nil, badData
		}
		tx[i].index = txzones[i]
		if i < len(isstd) {
			tx[i].isstd = isstd[i] != 0
		}
		if i < len(isutc) {
			tx[i].isutc = isutc[i] != 0
		}
	}

	if len(tx) == 0 {
		// Build fake transition to cover all time.
		// This happens in fixed locations like "Etc/GMT0".
		tx = append(tx, zoneTrans{when: alpha, index: 0})
	}

	// Committed to succeed.
	l = &Location{zone: zone, tx: tx}

	// Fill in the cache with information about right now,
	// since that will be the most common lookup.
	sec := time.Now().UTC().Unix()
	for i := range tx {
		if tx[i].when <= sec && (i+1 == len(tx) || sec < tx[i+1].when) {
			l.cacheStart = tx[i].when
			l.cacheEnd = omega
			if i+1 < len(tx) {
				l.cacheEnd = tx[i+1].when
			}
			l.cacheZone = &l.zone[tx[i].index]
		}
	}

	return l, nil
}

func loadZoneFile(dir, name string) (l *Location, err error) {
	if len(dir) > 4 && dir[len(dir)-4:] == ".zip" {
		return loadZoneZip(dir, name)
	}
	if dir != "" {
		name = dir + "/" + name
	}
	buf, err := readFile(name)
	if err != nil {
		return
	}
	return loadZoneData(buf)
}

// There are 500+ zoneinfo files. Rather than distribute them all
// individually, we ship them in an uncompressed zip file.
// Used this way, the zip file format serves as a commonly readable
// container for the individual small files. We choose zip over tar
// because zip files have a contiguous table of contents, making
// individual file lookups faster, and because the per-file overhead
// in a zip file is considerably less than tar's 512 bytes.

// get4 returns the little-endian 32-bit value in b.
func get4(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24
}

// get2 returns the little-endian 16-bit value in b.
func get2(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	return int(b[0]) | int(b[1])<<8
}

func loadZoneZip(zipfile, name string) (l *Location, err error) {
	fd, err := open(zipfile)
	if err != nil {
		return nil, errors.New("open " + zipfile + ": " + err.Error())
	}
	defer closefd(fd)

	const (
		zecheader = 0x06054b50
		zcheader  = 0x02014b50
		ztailsize = 22

		zheadersize = 30
		zheader     = 0x04034b50
	)

	buf := make([]byte, ztailsize)
	if err := preadn(fd, buf, -ztailsize); err != nil || get4(buf) != zecheader {
		return nil, errors.New("corrupt zip file " + zipfile)
	}
	n := get2(buf[10:])
	size := get4(buf[12:])
	off := get4(buf[16:])

	buf = make([]byte, size)
	if err := preadn(fd, buf, off); err != nil {
		return nil, errors.New("corrupt zip file " + zipfile)
	}

	for i := 0; i < n; i++ {
		// zip entry layout:
		//	0	magic[4]
		//	4	madevers[1]
		//	5	madeos[1]
		//	6	extvers[1]
		//	7	extos[1]
		//	8	flags[2]
		//	10	meth[2]
		//	12	modtime[2]
		//	14	moddate[2]
		//	16	crc[4]
		//	20	csize[4]
		//	24	uncsize[4]
		//	28	namelen[2]
		//	30	xlen[2]
		//	32	fclen[2]
		//	34	disknum[2]
		//	36	iattr[2]
		//	38	eattr[4]
		//	42	off[4]
		//	46	name[namelen]
		//	46+namelen+xlen+fclen - next header
		//
		if get4(buf) != zcheader {
			break
		}
		meth := get2(buf[10:])
		size := get4(buf[24:])
		namelen := get2(buf[28:])
		xlen := get2(buf[30:])
		fclen := get2(buf[32:])
		off := get4(buf[42:])
		zname := buf[46 : 46+namelen]
		buf = buf[46+namelen+xlen+fclen:]
		if string(zname) != name {
			continue
		}
		if meth != 0 {
			return nil, errors.New("unsupported compression for " + name + " in " + zipfile)
		}

		// zip per-file header layout:
		//	0	magic[4]
		//	4	extvers[1]
		//	5	extos[1]
		//	6	flags[2]
		//	8	meth[2]
		//	10	modtime[2]
		//	12	moddate[2]
		//	14	crc[4]
		//	18	csize[4]
		//	22	uncsize[4]
		//	26	namelen[2]
		//	28	xlen[2]
		//	30	name[namelen]
		//	30+namelen+xlen - file data
		//
		buf = make([]byte, zheadersize+namelen)
		if err := preadn(fd, buf, off); err != nil ||
			get4(buf) != zheader ||
			get2(buf[8:]) != meth ||
			get2(buf[26:]) != namelen ||
			string(buf[30:30+namelen]) != name {
			return nil, errors.New("corrupt zip file " + zipfile)
		}
		xlen = get2(buf[28:])

		buf = make([]byte, size)
		if err := preadn(fd, buf, off+30+namelen+xlen); err != nil {
			return nil, errors.New("corrupt zip file " + zipfile)
		}

		return loadZoneData(buf)
	}

	return nil, errors.New("cannot find " + name + " in zip file " + zipfile)
}

func initTestingZone() {
	z, err := loadZoneFile(runtime.GOROOT()+"/lib/time/zoneinfo.zip", "America/Los_Angeles")
	if err != nil {
		panic("cannot load America/Los_Angeles for testing: " + err.Error())
	}
	z.name = "Local"
	localLoc = *z
}

// Many systems use /usr/share/zoneinfo, Solaris 2 has
// /usr/share/lib/zoneinfo, IRIX 6 has /usr/lib/locale/TZ.
var zoneDirs = []string{
	"/usr/share/zoneinfo/",
	"/usr/share/lib/zoneinfo/",
	"/usr/lib/locale/TZ/",
	runtime.GOROOT() + "/lib/time/zoneinfo.zip",
}

var origZoneDirs = zoneDirs

func forceZipFileForTesting(zipOnly bool) {
	zoneDirs = make([]string, len(origZoneDirs))
	copy(zoneDirs, origZoneDirs)
	if zipOnly {
		for i := 0; i < len(zoneDirs)-1; i++ {
			zoneDirs[i] = "/XXXNOEXIST"
		}
	}
}

func initLocal() {
	// consult $TZ to find the time zone to use.
	// no $TZ means use the system default /etc/localtime.
	// $TZ="" means use UTC.
	// $TZ="foo" means use /usr/share/zoneinfo/foo.

	tz, ok := syscall.Getenv("TZ")
	switch {
	case !ok:
		z, err := loadZoneFile("", "/etc/localtime")
		if err == nil {
			localLoc = *z
			localLoc.name = "Local"
			return
		}
	case tz != "" && tz != "UTC":
		if z, err := loadLocation(tz); err == nil {
			localLoc = *z
			return
		}
	}

	// Fall back to UTC.
	localLoc.name = "UTC"
}

func loadLocation(name string) (*Location, error) {
	var firstErr error
	for _, zoneDir := range zoneDirs {
		if z, err := loadZoneFile(zoneDir, name); err == nil {
			z.name = name
			return z, nil
		} else if firstErr == nil && !isNotExist(err) {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errors.New("unknown time zone " + name)
}

// for testing: whatever interrupts a sleep
func interrupt() {
	syscall.Kill(syscall.Getpid(), syscall.SIGCHLD)
}

// readFile reads and returns the content of the named file.
// It is a trivial implementation of ioutil.ReadFile, reimplemented
// here to avoid depending on io/ioutil or os.
// It returns an error if name exceeds maxFileSize bytes.
func readFile(name string) ([]byte, error) {
	f, err := syscall.Open(name, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(f)
	var (
		buf [4096]byte
		ret []byte
		n   int
	)
	for {
		n, err = syscall.Read(f, buf[:])
		if n > 0 {
			ret = append(ret, buf[:n]...)
		}
		if n == 0 || err != nil {
			break
		}
		if len(ret) > maxFileSize {
			return nil, fileSizeError(name)
		}
	}
	return ret, err
}

func open(name string) (uintptr, error) {
	fd, err := syscall.Open(name, syscall.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}
	return uintptr(fd), nil
}

func closefd(fd uintptr) {
	syscall.Close(int(fd))
}

func preadn(fd uintptr, buf []byte, off int) error {
	whence := seekStart
	if off < 0 {
		whence = seekEnd
	}
	if _, err := syscall.Seek(int(fd), int64(off), whence); err != nil {
		return err
	}
	for len(buf) > 0 {
		m, err := syscall.Read(int(fd), buf)
		if m <= 0 {
			if err == nil {
				return errors.New("short read")
			}
			return err
		}
		buf = buf[m:]
	}
	return nil
}

func isNotExist(err error) bool { return err == syscall.ENOENT }
