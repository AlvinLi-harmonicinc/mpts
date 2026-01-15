package mpts

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MPEG-H 3D Audio packet types (ISO/IEC 23008-3)
var MpeghAudioPacketType []string = []string{
	"PACTYP_FILLDATA",      // 0
	"PACTYP_MPEGH3DACFG",   // 1 - Config
	"PACTYP_MPEGH3DAFRAME", // 2 - Audio Frame
	"PACTYP_AUDIOSCENEINFO", // 3
	"PACTYP_SYNC",          // 6
	"PACTYP_SYNCGAP",       // 7
	"PACTYP_MARKER",        // 8
	"PACTYP_CRC16",         // 9
	"PACTYP_CRC32",         // 10
	"PACTYP_DESCRIPTOR",    // 11
	"PACTYP_USERINTERACTION", // 12
	"PACTYP_LOUDNESS_DRC",  // 13
	"PACTYP_BUFFERINFO",    // 14
	"PACTYP_GLOBAL_CRC16",  // 15
	"PACTYP_GLOBAL_CRC32",  // 16
	"PACTYP_AUDIOTRUNCATION", // 17
	"PACTYP_GENDATA",       // 18
}

func GetMpeghAudioPacketType(packetType int) string {
	// Handle label values (upper 3 bits determine packet type for some values)
	actualType := packetType
	
	typeMap := map[int]string{
		0:  MpeghAudioPacketType[0],
		1:  MpeghAudioPacketType[1],
		2:  MpeghAudioPacketType[2],
		3:  MpeghAudioPacketType[3],
		6:  MpeghAudioPacketType[4],
		7:  MpeghAudioPacketType[5],
		8:  MpeghAudioPacketType[6],
		9:  MpeghAudioPacketType[7],
		10: MpeghAudioPacketType[8],
		11: MpeghAudioPacketType[9],
		12: MpeghAudioPacketType[10],
		13: MpeghAudioPacketType[11],
		14: MpeghAudioPacketType[12],
		15: MpeghAudioPacketType[13],
		16: MpeghAudioPacketType[14],
		17: MpeghAudioPacketType[15],
		18: MpeghAudioPacketType[16],
	}
	if ptype, ok := typeMap[actualType]; ok {
		return ptype
	}
	return fmt.Sprintf("unknown_%d", packetType)
}

type MhasPacketInfo struct {
	Pos         int64
	Pts         int64
	PacketTypes []string
}

type MpeghAudioRecord struct {
	BaseRecord
	curpkt        *PesPkt
	Pkts          []*PesPkt
	MhasPackets   []MhasPacketInfo
	RapFrames     []int64 // Positions of RAP frames
	RapLog        *os.File
	WorkaroundPESFlag bool
	WorkaroundPES     []byte
}

const minMpeghAudioPesHeaderLen = 19

func (s *MpeghAudioRecord) LogRap(i IFrameInfo) {
	if s.RapLog == nil {
		var pid string = strconv.Itoa(s.Pid)
		var err error
		fname := filepath.Join(s.Root, pid+"-rap"+".csv")
		s.RapLog, err = os.Create(fname)
		if err != nil {
			panic(err)
		}
		header := "Pos, PTS, Key"
		fmt.Fprintln(s.RapLog, header)
	}
	cols := []string{
		strconv.FormatInt(i.Pos, 10),
		strconv.FormatInt(i.Pts, 10),
		strconv.FormatBool(i.Key),
	}
	fmt.Fprintln(s.RapLog, strings.Join(cols, ", "))
}

func (s *MpeghAudioRecord) Process(pkt *TsPkt) {
	s.LogAdaptFieldPrivData(pkt)
	if pkt.PUSI == 1 {
		if s.curpkt != nil {
			// Parse MHAS packets to detect RAP
			isRap := s.parseMhasPackets(s.curpkt.Data, s.curpkt.Pos, s.curpkt.Pts)
			if isRap {
				info := IFrameInfo{}
				info.Pos = s.curpkt.Pos
				info.Pts = s.curpkt.Pts
				info.Key = true
				s.LogRap(info)
				s.RapFrames = append(s.RapFrames, s.curpkt.Pos)
			}
			s.Pkts = append(s.Pkts, s.curpkt)
		}
		s.curpkt = &PesPkt{}
		s.curpkt.Pos = pkt.Pos
		s.curpkt.Pcr = s.BaseRecord.PcrTime

		if len(pkt.Data) >= minMpeghAudioPesHeaderLen {
			var startcode = []byte{0, 0, 1}
			if 0 == bytes.Compare(startcode, pkt.Data[0:3]) {
				hlen := s.curpkt.Read(pkt.Data)
				pkt.Data = pkt.Data[hlen:]
			} else {
				log.Println("PES start code error")
			}
		} else {
			log.Println("Workaround for pkt:", pkt.Pos, "size:", len(pkt.Data))
			s.WorkaroundPESFlag = true
			s.WorkaroundPES = nil
		}
	}

	if s.WorkaroundPESFlag {
		s.WorkaroundPES = append(s.WorkaroundPES, pkt.Data...)
		pkt.Data = nil
		if len(s.WorkaroundPES) >= minMpeghAudioPesHeaderLen {
			var startcode = []byte{0, 0, 1}
			if 0 == bytes.Compare(startcode, s.WorkaroundPES[0:3]) {
				hlen := s.curpkt.Read(s.WorkaroundPES)
				pkt.Data = s.WorkaroundPES[hlen:]
				s.WorkaroundPESFlag = false
			} else {
				log.Println("PES start code error")
			}
		}
	}

	if s.curpkt != nil {
		s.curpkt.Size += int64(len(pkt.Data))
		s.curpkt.Data = append(s.curpkt.Data, pkt.Data...)
	}
}

// Parse MHAS escapedValue encoding
func parseEscapedValue(r *Reader, nBits, mBits, kBits int) uint64 {
	val := uint64(r.ReadBit64(nBits))
	maxVal := uint64((1 << nBits) - 1)
	
	if val == maxVal {
		val2 := uint64(r.ReadBit64(mBits))
		val = val + val2
		maxVal2 := uint64((1 << mBits) - 1)
		
		if val2 == maxVal2 {
			val3 := uint64(r.ReadBit64(kBits))
			val = val + val3
		}
	}
	
	return val
}

func (s *MpeghAudioRecord) parseMhasPackets(data []byte, pos int64, pts int64) bool {
	// MHAS Packet Layout (ISO/IEC 23008-3):
	// MHASPacketType = escapedValue(3,8,8)
	// MHASPacketLabel = escapedValue(2,8,32)
	// MHASPacketLength = escapedValue(11,24,24)
	// MHASPacketPayload(MHASPacketType)
	
	var isRap bool = false
	var packetTypes []string
	
	r := &Reader{Data: data}
	
	for r.Base < len(data) {
		// Check if we have enough data for at least the minimum packet header
		if r.Base+2 > len(data) {
			break
		}
		
		startPos := r.Base
		startOff := r.Off
		
		// Parse MHASPacketType - escapedValue(3,8,8)
		packetType := parseEscapedValue(r, 3, 8, 8)
		
		// Parse MHASPacketLabel - escapedValue(2,8,32)
		_ = parseEscapedValue(r, 2, 8, 32) // packetLabel not currently used
		
		// Parse MHASPacketLength - escapedValue(11,24,24)
		packetLength := parseEscapedValue(r, 11, 24, 24)
		
		// Validate packet length
		if packetLength > uint64(len(data)-r.Base) {
			// Invalid packet, try to resync
			r.Base = startPos + 1
			r.Off = startOff
			continue
		}
		
		packetTypes = append(packetTypes, GetMpeghAudioPacketType(int(packetType)))
		
		// Check for RAP indicators based on packet type:
		// PACTYP_MPEGH3DACFG (1) - Config packet indicates RAP
		// PACTYP_SYNC (6) - Sync packet
		if packetType == 1 || packetType == 6 {
			isRap = true
		}
		
		// Skip to next packet (advance by payload length)
		r.SkipByte(int(packetLength))
	}
	
	if len(packetTypes) > 0 {
		s.MhasPackets = append(s.MhasPackets, MhasPacketInfo{
			Pos:         pos,
			Pts:         pts,
			PacketTypes: packetTypes,
		})
	}
	
	return isRap
}

func (s *MpeghAudioRecord) Flush() {
	if s.curpkt != nil {
		s.parseMhasPackets(s.curpkt.Data, s.curpkt.Pos, s.curpkt.Pts)
		s.Pkts = append(s.Pkts, s.curpkt)
	}
}

func (s *MpeghAudioRecord) Report(root string) {
	var fname string
	var w *os.File
	var err error
	var pid string = strconv.Itoa(s.Pid)
	var header string

	// Close RAP log if it was created
	if s.RapLog != nil {
		s.RapLog.Close()
	}

	fname = filepath.Join(root, pid+".csv")
	w, err = os.Create(fname)
	if err != nil {
		panic(err)
	}
	header = "Pos, Size, PCR, PTS, DTS, (DTS-PCR)"
	fmt.Fprintln(w, header)
	for _, p := range s.Pkts {
		pcr := p.Pcr / 300
		dts := p.Dts
		if dts == 0 {
			dts = p.Pts
		}
		cols := []string{
			strconv.FormatInt(p.Pos, 10),
			strconv.FormatInt(p.Size, 10),
			strconv.FormatInt(pcr, 10),
			strconv.FormatInt(p.Pts, 10),
			strconv.FormatInt(dts, 10),
			strconv.FormatInt(dts-pcr, 10),
		}
		fmt.Fprintln(w, strings.Join(cols, ", "))
	}
	w.Close()

	if len(s.MhasPackets) > 0 {
		fname = filepath.Join(root, pid+"-mhas"+".csv")
		w, err = os.Create(fname)
		if err != nil {
			panic(err)
		}
		header = "Pos, PTS, MHAS Packet Types"
		fmt.Fprintln(w, header)
		for _, mhasInfo := range s.MhasPackets {
			cols := []string{
				strconv.FormatInt(mhasInfo.Pos, 10),
				strconv.FormatInt(mhasInfo.Pts, 10),
				strings.Join(mhasInfo.PacketTypes, ", "),
			}
			fmt.Fprintln(w, strings.Join(cols, ", "))
		}
		w.Close()
	}
}
