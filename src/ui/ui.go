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

func StartSniffer(m *PacketItemModel, stopSignal chan bool) {
	// Clean existing content
	m.items = make([]*Amelyzer.PacketItem, 0)
	m.PublishRowsReset()
	//

}

func StopSniffer(stopSignal chan bool) {
	stopSignal <- true
}

func MakeUI() error {
	var inBPFFilter *walk.LineEdit
	var outTE *walk.TextEdit
	var runningStateLineEdit *walk.LineEdit
	var PacketItemTableView *walk.TableView
	var startPushBotton *walk.PushButton
	var stopPushBotton *walk.PushButton
	var GlobalPacketItemModel = new(PacketItemModel)
	GlobalPacketItemModel.items = make([]*Amelyzer.PacketItem, 0)
	GlobalPacketItemModel.PublishRowsReset()
	//var stopSnifferSignal = make(chan bool)
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
							LineEdit{
								AssignTo: &runningStateLineEdit,
								Name:     "State",
								Text:     "Not Running!",
								Enabled:  false,
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
							PushButton{AssignTo: &startPushBotton, Name: "Start", Text: "Start", OnClicked: func() {
								runningStateLineEdit.SetText("Sniffing...")
								startPushBotton.SetEnabled(false)
								stopPushBotton.SetEnabled(true)
								//go StartSniffer(&GlobalPacketItemModel, stopSnifferSignal)
							}},
							PushButton{AssignTo: &stopPushBotton, Name: "Stop", Text: "Stop", OnClicked: func() {
								//go StopSniffer(stopSnifferSignal)
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
							PushButton{Name: "ApplyBPFFilter", Text: "Apply BPF Filter"},
							PushButton{Name: "QuickFiter", Text: "Quick Filter"},
							PushButton{Name: "Analyzer", Text: "Analyze Selected Packet"},
						},
					},
				},
			},
			HSplitter{
				MinSize: Size{Height: 760},
				Children: []Widget{
					TableView{
						AssignTo:         &PacketItemTableView,
						Name:             "tableView", // Name is needed for settings persistence
						AlternatingRowBG: true,
						ColumnsOrderable: true,
						Columns: []TableViewColumn{
							// Name is needed for settings persistence
							{Name: "#", DataMember: "No."}, // Use DataMember, if names differ
							{Name: "Time"},
							{Name: "Source"},
							{Name: "Destination"},
							{Name: "Protocol"},
							{Name: "Length"},
							{Name: "Info"},
						},
						Model: GlobalPacketItemModel,
					},

					TextEdit{
						Name:     "Packet Detail",
						AssignTo: &outTE,
						ReadOnly: true,
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
