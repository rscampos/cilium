//go:build freebsd && arm64
// +build freebsd,arm64

// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs process/types_freebsd.go

package process

const (
	CTLKern          = 1
	KernProc         = 14
	KernProcPID      = 1
	KernProcProc     = 8
	KernProcPathname = 12
	KernProcArgs     = 7
)

const (
	sizeofPtr      = 0x8
	sizeofShort    = 0x2
	sizeofInt      = 0x4
	sizeofLong     = 0x8
	sizeofLongLong = 0x8
)

const (
	sizeOfKinfoVmentry = 0x488
	sizeOfKinfoProc    = 0x440
)

const (
	SIDL   = 1
	SRUN   = 2
	SSLEEP = 3
	SSTOP  = 4
	SZOMB  = 5
	SWAIT  = 6
	SLOCK  = 7
)

type (
	_C_short     int16
	_C_int       int32
	_C_long      int64
	_C_long_long int64
)

type Timespec struct {
	Sec  int64
	Nsec int64
}

type Timeval struct {
	Sec  int64
	Usec int64
}

type Rusage struct {
	Utime    Timeval
	Stime    Timeval
	Maxrss   int64
	Ixrss    int64
	Idrss    int64
	Isrss    int64
	Minflt   int64
	Majflt   int64
	Nswap    int64
	Inblock  int64
	Oublock  int64
	Msgsnd   int64
	Msgrcv   int64
	Nsignals int64
	Nvcsw    int64
	Nivcsw   int64
}

type Rlimit struct {
	Cur int64
	Max int64
}

type KinfoProc struct {
	Structsize     int32
	Layout         int32
	Args           *int64 /* pargs */
	Paddr          *int64 /* proc */
	Addr           *int64 /* user */
	Tracep         *int64 /* vnode */
	Textvp         *int64 /* vnode */
	Fd             *int64 /* filedesc */
	Vmspace        *int64 /* vmspace */
	Wchan          *byte
	Pid            int32
	Ppid           int32
	Pgid           int32
	Tpgid          int32
	Sid            int32
	Tsid           int32
	Jobc           int16
	Spare_short1   int16
	Tdev_freebsd11 uint32
	Siglist        [16]byte /* sigset */
	Sigmask        [16]byte /* sigset */
	Sigignore      [16]byte /* sigset */
	Sigcatch       [16]byte /* sigset */
	Uid            uint32
	Ruid           uint32
	Svuid          uint32
	Rgid           uint32
	Svgid          uint32
	Ngroups        int16
	Spare_short2   int16
	Groups         [16]uint32
	Size           uint64
	Rssize         int64
	Swrss          int64
	Tsize          int64
	Dsize          int64
	Ssize          int64
	Xstat          uint16
	Acflag         uint16
	Pctcpu         uint32
	Estcpu         uint32
	Slptime        uint32
	Swtime         uint32
	Cow            uint32
	Runtime        uint64
	Start          Timeval
	Childtime      Timeval
	Flag           int64
	Kiflag         int64
	Traceflag      int32
	Stat           uint8
	Nice           int8
	Lock           uint8
	Rqindex        uint8
	Oncpu_old      uint8
	Lastcpu_old    uint8
	Tdname         [17]uint8
	Wmesg          [9]uint8
	Login          [18]uint8
	Lockname       [9]uint8
	Comm           [20]int8
	Emul           [17]uint8
	Loginclass     [18]uint8
	Moretdname     [4]uint8
	Sparestrings   [46]uint8
	Spareints      [2]int32
	Tdev           uint64
	Oncpu          int32
	Lastcpu        int32
	Tracer         int32
	Flag2          int32
	Fibnum         int32
	Cr_flags       uint32
	Jid            int32
	Numthreads     int32
	Tid            int32
	Pri            Priority
	Rusage         Rusage
	Rusage_ch      Rusage
	Pcb            *int64 /* pcb */
	Kstack         *byte
	Udata          *byte
	Tdaddr         *int64 /* thread */
	Spareptrs      [6]*byte
	Sparelongs     [12]int64
	Sflag          int64
	Tdflags        int64
}

type Priority struct {
	Class  uint8
	Level  uint8
	Native uint8
	User   uint8
}

type KinfoVmentry struct {
	Structsize        int32
	Type              int32
	Start             uint64
	End               uint64
	Offset            uint64
	Vn_fileid         uint64
	Vn_fsid_freebsd11 uint32
	Flags             int32
	Resident          int32
	Private_resident  int32
	Protection        int32
	Ref_count         int32
	Shadow_count      int32
	Vn_type           int32
	Vn_size           uint64
	Vn_rdev_freebsd11 uint32
	Vn_mode           uint16
	Status            uint16
	Vn_fsid           uint64
	Vn_rdev           uint64
	X_kve_ispare      [8]int32
	Path              [1024]uint8
}
