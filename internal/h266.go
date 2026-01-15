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

// VVC/H.266 NAL unit types (ISO/IEC 23090-3)
var VvcNalUnitType []string = []string{
	"trail_nvc",      // 0
	"stsa_nvc",       // 1
	"radl_nvc",       // 2
	"rasl_nvc",       // 3
	"rsv_vcl_4",      // 4
	"rsv_vcl_5",      // 5
	"rsv_vcl_6",      // 6
	"idr_w_radl",     // 7 - IDR with RADL
	"idr_n_lp",       // 8 - IDR no leading pictures (RAP)
	"cra_nut",        // 9 - Clean Random Access (RAP)
	"gdr_nut",        // 10 - Gradual Decoder Refresh
	"rsv_irap_11",    // 11
	"opi_nut",        // 12 - Operating Point Information
	"dci_nut",        // 13 - Decoding Capability Information
	"vps_nut",        // 14 - Video Parameter Set
	"sps_nut",        // 15 - Sequence Parameter Set
	"pps_nut",        // 16 - Picture Parameter Set
	"prefix_aps_nut", // 17 - Adaptation Parameter Set (Prefix)
	"suffix_aps_nut", // 18 - Adaptation Parameter Set (Suffix)
	"ph_nut",         // 19 - Picture Header
	"aud_nut",        // 20 - Access Unit Delimiter
	"eob_nut",        // 21 - End of Bitstream
	"eos_nut",        // 22 - End of Sequence
	"prefix_sei_nut", // 23 - Supplemental Enhancement Information (Prefix)
	"suffix_sei_nut", // 24 - Supplemental Enhancement Information (Suffix)
	"fd_nut",         // 25 - Filler Data
	"rsv_nvcl_26",    // 26
	"rsv_nvcl_27",    // 27
	"unspec_28",      // 28
	"unspec_29",      // 29
	"unspec_30",      // 30
	"unspec_31",      // 31
}

func GetVvcNalUnitType(b int) string {
	// VVC NAL unit type is in bits [4:0] of the first byte after start code
	// NAL header is 2 bytes: |F|Z| LayerID[5:0] | TID[2:0] | Type[4:0] |
	nalType := (b >> 3) & 0x1F
	if nalType < len(VvcNalUnitType) {
		return VvcNalUnitType[nalType]
	}
	return "unknown"
}

func ParseVvcNalUnits(data []byte) []string {
	var nals []string
	var pos int
	var startcode = []byte{0, 0, 1}
	var startlen = len(startcode)
	for pos+5 < len(data) {
		if bytes.Compare(startcode, data[pos:pos+startlen]) == 0 {
			pos += startlen
			// VVC uses 2-byte NAL header
			if pos+1 < len(data) {
				nalHeaderByte1 := int(data[pos+1])
				nal := GetVvcNalUnitType(nalHeaderByte1)
				nals = append(nals, nal)
			}
		}
		pos += 1
	}
	return nals
}

type NalInfo struct {
	Pos  int64
	Pts  int64
	Nals []string
}

type H266Record struct {
	BaseRecord
	curpkt *PesPkt
	Pkts   []*PesPkt
	NalInfos []NalInfo
	// Workaround PES parsing error
	WorkaroundPESFlag bool
	WorkaroundPES     []byte
}

const minVvcPesHeaderLen = 19

func (s *H266Record) Process(pkt *TsPkt) {
	s.LogAdaptFieldPrivData(pkt)
	if pkt.PUSI == 1 {
		if s.curpkt != nil {
			nals := ParseVvcNalUnits(s.curpkt.Data)
			for _, nal := range nals {
				// VVC RAP (Random Access Point) NAL units: IDR and CRA
				if nal == "idr_w_radl" || nal == "idr_n_lp" || nal == "cra_nut" {
					info := IFrameInfo{}
					info.Pos = s.curpkt.Pos
					info.Pts = s.curpkt.Pts
					info.Key = true
					s.LogIFrame(info)
				}
			}
			s.NalInfos = append(s.NalInfos, NalInfo{
				Pos:  s.curpkt.Pos,
				Pts:  s.curpkt.Pts,
				Nals: nals,
			})
			s.Pkts = append(s.Pkts, s.curpkt)
		}
		s.curpkt = &PesPkt{}
		s.curpkt.Pos = pkt.Pos
		s.curpkt.Pcr = s.BaseRecord.PcrTime

		if len(pkt.Data) >= minVvcPesHeaderLen {
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
		if len(s.WorkaroundPES) >= minVvcPesHeaderLen {
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

func (s *H266Record) Flush() {
	if s.curpkt != nil {
		nals := ParseVvcNalUnits(s.curpkt.Data)
		s.NalInfos = append(s.NalInfos, NalInfo{
			Pos:  s.curpkt.Pos,
			Pts:  s.curpkt.Pts,
			Nals: nals,
		})
		s.Pkts = append(s.Pkts, s.curpkt)
	}
}

func (s *H266Record) Report(root string) {
	var fname string
	var w *os.File
	var err error
	var pid string = strconv.Itoa(s.Pid)
	var header string

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

	fname = filepath.Join(root, pid+"-nal"+".csv")
	w, err = os.Create(fname)
	if err != nil {
		panic(err)
	}
	header = "Pos, PTS, NAL units"
	fmt.Fprintln(w, header)
	for _, nalInfo := range s.NalInfos {
		cols := []string{
			strconv.FormatInt(nalInfo.Pos, 10),
			strconv.FormatInt(nalInfo.Pts, 10),
			strings.Join(nalInfo.Nals, ", "),
		}
		fmt.Fprintln(w, strings.Join(cols, ", "))
	}
	w.Close()
}
