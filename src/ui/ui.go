package ui

import (
	Amelyzer "Amelyzer/src/network"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"sort"
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

// RowCount Called by the TableView from SetModel and every time the model publishes a RowsReset event.
func (m *PacketItemModel) RowCount() int {
	return len(m.items)
}

// Value Called by the TableView when it needs the text to display for a given cell.
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

// Sort Called by the TableView to sort the model.
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

func StartSniffer(m *PacketItemModel, stopSignal chan bool, deviceName string, BPFFilter string) {
	PacketDetailPool = make([]Amelyzer.PacketDetail, 0)
	PacketItemPool = make([]Amelyzer.PacketItem, 0)
	m.items = make([]*Amelyzer.PacketItem, 0)
	m.PublishRowsReset()
	var itemsIn = make(chan Amelyzer.PacketItem)
	var detailsIn = make(chan Amelyzer.PacketDetail)
	configure := Amelyzer.SnifferConfigure{
		DeviceName:     deviceName,
		SnapshotLength: 1500,
		NicMix:         false,
		Timeout:        -1,
		BPFFilter:      BPFFilter,
	}
	go Amelyzer.StartSniffer(configure, itemsIn, detailsIn, stopSignal)
	for {
		var itemIn Amelyzer.PacketItem
		var detailIn Amelyzer.PacketDetail
		select {
		case itemIn = <-itemsIn:
			PacketItemPool = append(PacketItemPool, itemIn)
			m.items = append(m.items, &PacketItemPool[len(PacketItemPool)-1])
			m.PublishRowsReset()
		case detailIn = <-detailsIn:
			PacketDetailPool = append(PacketDetailPool, detailIn)
		}
	}
	m.PublishRowsReset()
}

func StopSniffer(stopSignal chan bool) {
	stopSignal <- true
}

func MakeUI() error {
	var inBPFFilter *walk.LineEdit
	var outPacketDetailLabel *walk.Label
	var runningStateLineEdit *walk.LineEdit
	var PacketItemTableView *walk.TableView
	var startPushBotton *walk.PushButton
	var stopPushBotton *walk.PushButton
	var devicesComboBox *walk.ComboBox

	var GlobalPacketItemModel = new(PacketItemModel)
	GlobalPacketItemModel.items = make([]*Amelyzer.PacketItem, 0)
	GlobalPacketItemModel.PublishRowsReset()

	var stopSnifferSignal = make(chan bool)
	var BPFFilter string = ""

	var devices = Amelyzer.ListDeviceName()
	var devicesName = make(map[string]string)
	var devicesDescription = make([]string, 0)
	for _, device := range devices {
		devicesDescription = append(devicesDescription, device.Description)
		devicesName[device.Description] = device.Name
	}

	mw := MainWindow{
		Name:  "mainWindow", // Name is needed for settings persistence
		Title: "Amelyzer",
		Layout: VBox{
			Margins: Margins{
				Left:   10,
				Top:    10,
				Right:  10,
				Bottom: 10,
			}},
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
									ComboBox{
										AssignTo: &devicesComboBox,
										Name:     "DevicesComboBox",
										Editable: false,
										Model:    devicesDescription,
									},
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
								AssignTo: &startPushBotton,
								Name:     "Start",
								Text:     "Start",
								OnClicked: func() {
									runningStateLineEdit.SetText("Sniffing...")
									startPushBotton.SetEnabled(false)
									stopPushBotton.SetEnabled(true)
									var deviceName string
									if devicesComboBox.Text() == "" {
										deviceName = devicesName[devicesDescription[0]]

									} else {
										deviceName = devicesName[devicesComboBox.Text()]
									}
									go StartSniffer(GlobalPacketItemModel, stopSnifferSignal, deviceName, BPFFilter)
								},
							},
							PushButton{AssignTo: &stopPushBotton, Name: "Stop", Text: "Stop", OnClicked: func() {
								go StopSniffer(stopSnifferSignal)
								runningStateLineEdit.SetText("Stopped...")
								startPushBotton.SetEnabled(true)
								stopPushBotton.SetEnabled(false)
							}},
						},
					},
					VSplitter{
						Children: []Widget{
							LineEdit{
								Name:    "Tips",
								Text:    "Choose Function",
								Enabled: false,
							},
							PushButton{Name: "ApplyBPFFilter", Text: "Apply BPF Filter", OnClicked: func() {
								BPFFilter = inBPFFilter.Text()
							}},
							PushButton{Name: "QuickFiter", Text: "Quick Filter"},
							PushButton{Name: "Analyzer", Text: "Analyze Selected Packet"},
						},
					},
				},
			},
			VSplitter{
				MinSize: Size{Height: 760},
				Children: []Widget{
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
							{Name: "Source"},
							{Name: "Target"},
							{Name: "Protocol"},
							{Name: "InfoShort"},
						},
						Model: GlobalPacketItemModel,
						OnItemActivated: func() {
							// Item的双击事件
							var currentIndex = PacketItemTableView.CurrentIndex()
							var itemNumber = GlobalPacketItemModel.items[currentIndex].Number
							var currentDetail = PacketDetailPool[itemNumber-1]
							var detailString = currentDetail.Layer2.Info + "\n" + currentDetail.Layer3.Info + "\n" +
								currentDetail.Layer4.Info
							outPacketDetailLabel.SetText(detailString)
						},
					},

					Label{
						Name:     "Packet Detail",
						AssignTo: &outPacketDetailLabel,
						Text:     "Packet Details",
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
