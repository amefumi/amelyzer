package ui

import (
	Amelyzer "Amelyzer/src/network"
	"fmt"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"sort"
	"time"
)

type PacketItemModel struct {
	walk.TableModelBase
	walk.SorterBase
	sortColumn int
	sortOrder  walk.SortOrder
	items      []*Amelyzer.PacketItem
}

var PacketDetailPool []Amelyzer.PacketDetail
var PacketItemPool []Amelyzer.PacketItem

var TCPTraced Amelyzer.TCPFlow

// TableViewStage  0:正常更新 1:需要先根据TCPTraced进行已有内容过滤 2:只展示TCPTraced内容 3:进行所有内容还原
var TableViewStage = 0

func (m *PacketItemModel) RowCount() int {
	return len(m.items)
}

func (m *PacketItemModel) Value(row, col int) interface{} {
	item := m.items[row]
	switch col {
	case 0:
		return item.Number
	case 1:
		return item.Time
	case 2:
		return item.Length
	case 3:
		return item.Source
	case 4:
		return item.Target
	case 5:
		return item.Protocol
	case 6:
		return item.InfoShort
	}
	panic("unexpected col")
}

func (m *PacketItemModel) Sort(col int, order walk.SortOrder) error {
	m.sortColumn, m.sortOrder = col, order

	sort.SliceStable(m.items, func(i, j int) bool {
		a, b := m.items[i], m.items[j]
		c := func(ls bool) bool {
			if m.sortOrder == walk.SortAscending {
				return ls
			}
			return !ls
		}
		switch m.sortColumn {
		case 0:
			return c(a.Number < b.Number)
		case 1:
			return c(a.Time < b.Time)
		case 2:
			return c(a.Length < b.Length)
		case 3:
			return c(a.Source < b.Source)
		case 4:
			return c(a.Target < b.Target)
		case 5:
			return c(a.Protocol <= b.Protocol)
		case 6:
			return c(a.InfoShort < b.InfoShort)
		}

		panic("unreachable")
	})
	return m.SorterBase.Sort(col, order)
}

var hb chan bool
var hbs bool

func HeartBeat() {
	hb <- true
	if hbs == true {
		time.AfterFunc(1*time.Second, HeartBeat)
	}
}

func StartSniffer(m *PacketItemModel, stopSignal chan bool, deviceName string, BPFFilter string) {
	PacketDetailPool = make([]Amelyzer.PacketDetail, 0)
	PacketItemPool = make([]Amelyzer.PacketItem, 0)
	m.items = make([]*Amelyzer.PacketItem, 0)
	m.PublishRowsReset()
	var itemsIn = make(chan Amelyzer.PacketItem)
	var detailsIn = make(chan Amelyzer.PacketDetail)
	fmt.Println(BPFFilter)
	configure := Amelyzer.SnifferConfigure{
		DeviceName:     deviceName,
		SnapshotLength: 1500,
		NicMix:         false,
		Timeout:        -1,
		BPFFilter:      BPFFilter,
	}
	var stopSignal1 chan bool
	go Amelyzer.StartSniffer(configure, itemsIn, detailsIn, stopSignal1)
	var p int = 0
	hbs = true
	go HeartBeat()
	for {
		var itemIn Amelyzer.PacketItem
		var detailIn Amelyzer.PacketDetail
		var heartBeat bool
		var stop bool
		select {
		case stop = <-stopSignal:
			stopSignal1 <- stop
			hbs = false
			return
		case itemIn = <-itemsIn:
			if itemIn.Number < 0 {
				continue
			}
			PacketItemPool = append(PacketItemPool, itemIn) // 同一次嗅探中不能改变PacketItemPool和PacketDetailPool的加入逻辑
			if TableViewStage == 0 {
				m.items = append(m.items, &PacketItemPool[len(PacketItemPool)-1])
				m.PublishRowsInserted(p, p+1)
				p++
				if p > 5000 {
					return // 最多5000条，太大会爆内存
				}
			} else if TableViewStage == 1 {
				m.items = make([]*Amelyzer.PacketItem, 0) // 新建一个m
				fmt.Println("Enter Stage 1")
				for i, _ := range PacketItemPool {
					p = 0
					if Amelyzer.IsSameTCPConnection(&TCPTraced, &PacketItemPool[i]) {
						m.items = append(m.items, &PacketItemPool[i])
						m.PublishRowsInserted(p, p+1)
						p++ // 逻辑上这里p不会大于5000
					}
				}
				TableViewStage = 2
				fmt.Println("Exit Stage 1")
			} else if TableViewStage == 2 {
				fmt.Println("Enter Stage 2")
				if Amelyzer.IsSameTCPConnection(&TCPTraced, &PacketItemPool[len(PacketItemPool)-1]) {
					m.items = append(m.items, &PacketItemPool[len(PacketItemPool)-1])
					m.PublishRowsInserted(p, p+1)
					p++
					if p > 5000 {
						return
					}
				}
				fmt.Println("Exit Stage 2")
			} else if TableViewStage == 3 {
				fmt.Println("Enter Stage 3")
				m.items = make([]*Amelyzer.PacketItem, 0) // 新建一个m
				for i, _ := range PacketItemPool {
					p = 0
					m.items = append(m.items, &PacketItemPool[i])
					m.PublishRowsInserted(p, p+1)
					p++ // 逻辑上这里p不会大于5000
					if p > 5000 {
						return
					}
				}
				TableViewStage = 0
				fmt.Println("Exit Stage 3")
			}

		case detailIn = <-detailsIn:
			PacketDetailPool = append(PacketDetailPool, detailIn)
		case heartBeat = <-hb:
			fmt.Println("HeartBeat:", heartBeat)
			itemsIn <- Amelyzer.PacketItem{
				Number: -1,
			}
		}
	}
}

func StopSniffer(stopSignal chan bool) {
	stopSignal <- true
}

func MakeUI() error {
	var mWind *walk.MainWindow
	icon, _ := walk.NewIconFromFile("./assets/app.ico")

	var inBPFFilter *walk.LineEdit
	var outPacketDetailLabel *walk.Label
	var outPacketDumpText *walk.TextEdit
	var outPacketBytesText *walk.TextEdit
	var runningStateLineEdit *walk.LineEdit
	var PacketItemTableView *walk.TableView
	var startPushButton *walk.PushButton
	var stopPushButton *walk.PushButton
	var setBPFFilterButton *walk.PushButton
	var setQuickFilterButton *walk.PushButton
	var analyzeButton *walk.PushButton
	var tcpTrackButton *walk.PushButton

	var devicesComboBox *walk.ComboBox

	var GlobalPacketItemModel = new(PacketItemModel)
	GlobalPacketItemModel.items = make([]*Amelyzer.PacketItem, 0)
	GlobalPacketItemModel.PublishRowsReset()

	var stopSnifferSignal = make(chan bool)
	var BPFFilter = ""

	var devices = Amelyzer.ListDeviceName()
	var devicesName = make(map[string]string)
	var devicesDescription = make([]string, 0)
	for _, device := range devices {
		devicesDescription = append(devicesDescription, device.Description)
		devicesName[device.Description] = device.Name
	}

	mw := MainWindow{
		AssignTo: &mWind,
		Name:     "mainWindow", // Name is needed for settings persistence
		Title:    "Amelyzer",
		Layout: VBox{
			Margins: Margins{
				Left:   10,
				Top:    10,
				Right:  10,
				Bottom: 10,
			},
		},
		Icon: icon,
		Children: []Widget{
			HSplitter{
				Children: []Widget{
					VSplitter{
						Children: []Widget{
							HSplitter{
								Children: []Widget{
									LineEdit{
										AssignTo: &runningStateLineEdit,
										Name:     "State",
										Text:     "Not Running!",
										Enabled:  false,
									},
									Label{Text: "Device:"},
									ComboBox{
										AssignTo: &devicesComboBox,
										Name:     "DevicesComboBox",
										Editable: false,
										Model:    devicesDescription,
									},
									HSpacer{},
								},
							},
							HSplitter{
								Children: []Widget{
									Label{
										Name: "eBPF",
										Text: "BPF Filter:",
									},
									LineEdit{
										Name:     "BPF Filter Edit",
										AssignTo: &inBPFFilter,
									},
								},
							},
							PushButton{
								AssignTo: &startPushButton,
								Name:     "Start",
								Text:     "Start",
								OnClicked: func() {
									err := runningStateLineEdit.SetText("Sniffing...")
									if err != nil {
										return
									}
									startPushButton.SetEnabled(false)
									stopPushButton.SetEnabled(true)
									setBPFFilterButton.SetEnabled(false)
									setQuickFilterButton.SetEnabled(false)
									//analyzeButton.SetEnabled(false)
									var deviceName string
									if devicesComboBox.Text() == "" {
										deviceName = devicesName[devicesDescription[0]]

									} else {
										deviceName = devicesName[devicesComboBox.Text()]
									}
									go StartSniffer(GlobalPacketItemModel, stopSnifferSignal, deviceName, BPFFilter)
								},
							},
							PushButton{
								AssignTo: &stopPushButton,
								Name:     "Stop",
								Text:     "Stop",
								OnClicked: func() {
									go StopSniffer(stopSnifferSignal)
									err := runningStateLineEdit.SetText("Stopped...")
									if err != nil {
										return
									}
									startPushButton.SetEnabled(true)
									stopPushButton.SetEnabled(false)
									setBPFFilterButton.SetEnabled(true)
									setQuickFilterButton.SetEnabled(true)
									//analyzeButton.SetEnabled(true)
								},
							},
						},
					},
					VSplitter{
						Children: []Widget{
							PushButton{
								Name:     "TCPTrack",
								AssignTo: &tcpTrackButton,
								Text:     "Track Current TCP Flow",
								OnClicked: func() {
									if TableViewStage == 0 {
										var currentIndex = PacketItemTableView.CurrentIndex()
										var itemNumber = GlobalPacketItemModel.items[currentIndex].Number
										var currentDetail = PacketDetailPool[itemNumber-1]
										if currentDetail.Layer4.Protocol != "TCP" {
											walk.MsgBox(mWind, "Flow Track Error", fmt.Sprintf("Protocol %s Track Unaccess.",
												currentDetail.Layer4.Protocol), walk.MsgBoxIconError)
										} else {
											TCPTraced = Amelyzer.TCPFlow{
												Addr1: currentDetail.Layer3.Src,
												Port1: currentDetail.Layer4.SrcPort,
												Addr2: currentDetail.Layer3.Dst,
												Port2: currentDetail.Layer4.DstPort,
											}
											TableViewStage = 1
											tcpTrackButton.SetText("Stop TCP Track")
										}
									} else {
										TableViewStage = 3
										tcpTrackButton.SetText("Track Current TCP Flow")
									}
								},
							},
							PushButton{
								Name:     "ApplyBPFFilter",
								AssignTo: &setBPFFilterButton,
								Text:     "Apply BPF Filter",
								OnClicked: func() {
									BPFFilter = inBPFFilter.Text()
								},
							},
							PushButton{
								Name:     "QuickFilter",
								AssignTo: &setQuickFilterButton,
								Text:     "Quick Filter",
								OnClicked: func() {
									go MakeQuickFilterUI(inBPFFilter, &BPFFilter, mWind)
								},
							},
							PushButton{
								Name:     "Analyzer",
								AssignTo: &analyzeButton,
								Text:     "Analyze Selected Packet",
								OnClicked: func() {
									var currentIndex = PacketItemTableView.CurrentIndex()
									var itemNumber = GlobalPacketItemModel.items[currentIndex].Number
									var currentDetail = PacketDetailPool[itemNumber-1]
									go MakeAnaylzerUI(&currentDetail, mWind)
								},
							},
						},
					},
				},
			},
			TableView{
				AssignTo:         &PacketItemTableView,
				Name:             "tableView", // Name is needed for settings persistence
				AlternatingRowBG: true,
				ColumnsOrderable: true,
				Columns: []TableViewColumn{
					// Name is needed for settings persistence
					{Name: "Number", DataMember: "No."}, // Use DataMember, if names differ
					{Name: "Time"},
					{Name: "Length"},
					//MinSize: Size{Height: 760},
					{Name: "Source"},
					{Name: "Target"},
					{Name: "Protocol"},
					{Name: "InfoShort"},
				},
				Model: GlobalPacketItemModel,
				OnItemActivated: func() {
					// Item的双击事件
					var currentIndex = PacketItemTableView.CurrentIndex()
					if currentIndex < 0 {
						currentIndex = 0
					}
					var itemNumber = GlobalPacketItemModel.items[currentIndex].Number
					var currentDetail = PacketDetailPool[itemNumber-1]
					var detailString = currentDetail.Layer2.Info + "\n" + currentDetail.Layer3.Info + "\n" +
						currentDetail.Layer4.Info + "\n" + currentDetail.Layer5.Info
					err := outPacketDetailLabel.SetText(detailString)
					if err != nil {
						return
					}
					var payloadBytes []byte
					var dumpString = ""
					if currentDetail.Layer4.Protocol == "UDP" || currentDetail.Layer4.Protocol == "TCP" {
						payloadBytes = currentDetail.Dump.TransportLayer().LayerPayload()
						dumpString = "[Transport Layer Payload] = "
					} else if currentDetail.Layer3.Protocol != "" && currentDetail.Layer3.Protocol != "ARP" {
						payloadBytes = currentDetail.Dump.NetworkLayer().LayerPayload()
						dumpString = "[Network Layer Payload] = "
					} else {
						payloadBytes = currentDetail.Dump.LinkLayer().LayerPayload()
						dumpString = "[Link Layer Payload] = "
					}
					for i, v := range payloadBytes {
						if v > 126 || v < 32 {
							payloadBytes[i] = '.'
						}
					}
					if len(payloadBytes) != 0 {
						dumpString += string(payloadBytes)
					}
					err = outPacketBytesText.SetText(fmt.Sprint(currentDetail.Dump.Data()))
					if err != nil {
						return
					}
					err = outPacketDumpText.SetText(dumpString)
					if err != nil {
						return
					}
				},
			},
			Label{
				Name:     "Packet Detail",
				AssignTo: &outPacketDetailLabel,
				Text:     "Packet Details",
			},
			HSplitter{
				Children: []Widget{
					TextEdit{
						Name:     "Packet Dump",
						AssignTo: &outPacketDumpText,
						Text:     "Packet Dump",
						VScroll:  true,
					},
					TextEdit{
						Name:     "Packet Bytes",
						AssignTo: &outPacketBytesText,
						Text:     "Packet Bytes",
						VScroll:  true,
					},
				},
			},
		},
	}
	if _, err := mw.Run(); err != nil {
		return err
	}

	return nil
}
