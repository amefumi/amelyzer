package ui

import (
	Amelyzer "Amelyzer/src/network"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func MakeUI() error {
	var inBPFFilter *walk.LineEdit
	var outTE *walk.TextEdit
	var outListBox *walk.ListBox
	mw := MainWindow{
		Name:    "mainWindow", // Name is needed for settings persistence
		Title:   "Amelyzer",
		MinSize: Size{Width: 800},
		Size:    Size{Width: 1600, Height: 900},
		Layout: VBox{
			Margins: Margins{
				Left:   20,
				Top:    20,
				Right:  20,
				Bottom: 20,
			}},
		Children: []Widget{
			HSplitter{
				Children: []Widget{
					VSplitter{
						Children: []Widget{
							Label{
								Name: "eBPF Filter",
								Text: "eBPF Filter:",
							},
							LineEdit{
								Name:     "BPF Filter Edit",
								AssignTo: &inBPFFilter,
							},
							PushButton{Name: "Start", Text: "Start", OnClicked: func() {

							}},
							PushButton{Name: "Stop", Text: "Stop", OnClicked: func() {
								Amelyzer.StopSniffer()
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
						//Model: NewFooModel(),
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
	if _, err := (mw.Run()); err != nil {
		return err
	}

	return nil
}
