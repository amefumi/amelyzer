package ui

import (
	Amelyzer "Amelyzer/src/network"
	"fmt"
	"github.com/cakturk/go-netstat/netstat"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"strconv"
)

type ConnectionModel struct {
	walk.TableModelBase
	items []*Amelyzer.Connection
}

func (m *ConnectionModel) RowCount() int {
	return len(m.items)
}

func (m *ConnectionModel) Value(row, col int) interface{} {
	item := m.items[row]
	switch col {
	case 0:
		return item.Protocol
	case 1:
		return item.Local
	case 2:
		return item.Remote
	case 3:
		return item.State
	case 4:
		return item.Process
	}
	panic("unexpected col")
}

func MakeAnaylzerUI(item *Amelyzer.PacketDetail, owner walk.Form) {
	if item.Layer4.Protocol != "TCP" && item.Layer4.Protocol != "UDP" {
		msg := fmt.Sprintf("Amelyzer is unable to analyzer not-TCP/UDP packet(%s). "+
			"Please wait for a REMOTE update.", item.Layer4.Protocol)
		walk.MsgBox(owner, "Unable to analyzer", msg, walk.MsgBoxIconError)
	} else {
		var add1 = item.Layer3.Src + ":" + strconv.Itoa(int(item.Layer4.SrcPort))
		var add2 = item.Layer3.Dst + ":" + strconv.Itoa(int(item.Layer4.DstPort))
		var e netstat.SockTabEntry
		if item.Layer4.Protocol == "TCP" {
			e = Amelyzer.FindTCPPort(add1, add2)
		} else {
			e = Amelyzer.FindUDPPort(add1, add2)
		}
		fmt.Println(add1, add2, e)
		if e.Process == nil {
			walk.MsgBox(owner, "Unable to analyzer", "Port has been deprecated/released.", walk.MsgBoxIconError)
		} else {
			currentPacketString := fmt.Sprintf("------------------------Current Packet------------------------\n\tFlow Type: %s\n\tLocal Address: %s\n\t"+
				"Remote Address: %s\n\tState: %s\n\tProcess: %s", item.Layer4.Protocol,
				e.LocalAddr.String(), e.RemoteAddr.String(), e.State.String(), e.Process.String())
			fmt.Print(currentPacketString)
			cl := Amelyzer.ProcessConnection(e.Process.String())
			fmt.Print(cl)
			var tableviewConnections *walk.TableView
			var modelConnections = new(ConnectionModel)
			modelConnections.items = make([]*Amelyzer.Connection, 0)
			modelConnections.PublishRowsReset()
			for _, c := range cl {
				var citem = c
				modelConnections.items = append(modelConnections.items, &citem)
			}
			fmt.Print(modelConnections.items)
			modelConnections.PublishRowsReset()
			an := Dialog{
				Name:  "Analyzer",
				Title: "Packet Analyzer",
				Layout: VBox{
					Margins: Margins{
						Left:   10,
						Top:    10,
						Right:  10,
						Bottom: 10,
					},
				},
				MinSize: Size{
					Width:  600,
					Height: 800,
				},
				Children: []Widget{
					Label{
						Name: "Port Usage",
						Text: currentPacketString,
					},
					Label{Text: "------------------------Same Process Flow------------------------"},
					TableView{
						AssignTo:         &tableviewConnections,
						Name:             "tableViewConnection",
						AlternatingRowBG: true,
						Columns: []TableViewColumn{
							{Name: "Protocol", DataMember: "Proto"},
							{Name: "Local"},
							{Name: "Remote"},
							{Name: "State"},
							{Name: "Process"},
						},
						Model: modelConnections,
					},
					Label{
						Name: "Slogan",
						Text: "If there is anything wrong with Amelyzer, Just CLose It!",
						Font: Font{
							Family:    "Arial",
							PointSize: 14,
							Italic:    true,
						},
					},
				},
			}
			//}
			if _, err := an.Run(owner); err != nil {
				fmt.Println(err)
				return
			}
		}
	}
}
