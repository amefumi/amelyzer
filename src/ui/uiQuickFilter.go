package ui

import (
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func MakeQuickFilterUI(inBPFLineEdit *walk.LineEdit, inBPFFilter *string, owner walk.Form) {
	//var generatedBPFFilter = ""

	var checkBoxHTTP *walk.CheckBox
	var checkBoxTCP *walk.CheckBox
	var checkBoxUDP *walk.CheckBox
	var checkBoxIPv4 *walk.CheckBox
	var checkBoxIPv6 *walk.CheckBox
	var checkBoxICMP *walk.CheckBox
	var lineEditPort *walk.LineEdit
	var lineEditHost *walk.LineEdit
	var dg *walk.Dialog
	qf := Dialog{
		AssignTo: &dg,
		Name:     "Quick Filter Generator",
		Title:    "Quick Filter",
		Layout: VBox{
			Margins: Margins{
				Left:   10,
				Top:    10,
				Right:  10,
				Bottom: 10,
			},
		},
		Children: []Widget{
			Label{Text: "Protocol Filter"},
			CheckBox{AssignTo: &checkBoxHTTP, Text: "HTTP"},
			CheckBox{AssignTo: &checkBoxTCP, Text: "TCP"},
			CheckBox{AssignTo: &checkBoxUDP, Text: "UDP"},
			CheckBox{AssignTo: &checkBoxIPv4, Text: "IPv4"},
			CheckBox{AssignTo: &checkBoxIPv6, Text: "IPv6"},
			CheckBox{AssignTo: &checkBoxICMP, Text: "ICMP"},
			Label{Text: "Port Filter"},
			LineEdit{AssignTo: &lineEditPort},
			Label{Text: "Host Filter"},
			LineEdit{AssignTo: &lineEditHost},
			PushButton{Text: "Apply", OnClicked: func() {
				var s = ""
				if checkBoxHTTP.Checked() {
					s += "http "
				}
				if checkBoxTCP.Checked() {
					s += "tcp "
				}
				if checkBoxUDP.Checked() {
					s += "udp "
				}
				if checkBoxIPv4.Checked() {
					s += "ipv4 "
				}
				if checkBoxIPv6.Checked() {
					s += "ipv6 "
				}
				if checkBoxICMP.Checked() {
					s += "icmp "
				}
				if lineEditHost.Text() != "" {
					s += "host " + lineEditHost.Text()
				}
				if lineEditPort.Text() != "" {
					s += "port " + lineEditPort.Text()
				}
				*inBPFFilter = s
				err := inBPFLineEdit.SetText(*inBPFFilter)
				if err != nil {
					return
				}
				dg.Close(0)
			}},
			PushButton{Text: "Cancel", OnClicked: func() {
				dg.Close(0)
			}},
		},
	}
	if _, err := qf.Run(owner); err != nil {
		return
	}
}
