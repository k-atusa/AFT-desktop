package main

import (
	"bytes"

	_ "golang.org/x/image/webp"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/k-atusa/USAG-Lib/Icons"
)

type MainExplorer struct {
	App         fyne.App
	Window      fyne.Window
	ContentArea *fyne.Container
	Info        LoginInfo
}

// ShowMain: 로그인 성공 후 호출되는 메인 진입점
func (e *MainExplorer) ShowMain(info LoginInfo) {
	e.Info = info
	e.Window = e.App.NewWindow("Stealth Vault Explorer - " + info.VaultPath)

	// --- [1. 상단 툴바] ---
	toolbar := widget.NewToolbar(
		widget.NewToolbarAction(theme.ContentAddIcon(), func() {}),
		widget.NewToolbarAction(theme.DocumentSaveIcon(), func() {}),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.SettingsIcon(), func() {}),
	)

	// --- [2. 좌측 트리 (가상화 지원)] ---
	// 실제 구현 시에는 account.webp에서 복호화된 데이터를 이 맵에 연결합니다.
	treeData := map[string][]string{
		"":          {"Documents", "Images", "root_secret.txt"},
		"Documents": {"passwords.txt", "bank_codes.txt"},
		"Images":    {"cloud.png", "aes.webp"},
	}

	tree := widget.NewTree(
		func(id string) []string { return treeData[id] },
		func(id string) bool {
			_, ok := treeData[id]
			return ok
		},
		func(branch bool) fyne.CanvasObject {
			if branch {
				return widget.NewLabel("Directory")
			}
			return widget.NewLabel("File")
		},
		func(id string, branch bool, obj fyne.CanvasObject) {
			l := obj.(*widget.Label)
			l.SetText(id)
			if branch {
				l.TextStyle = fyne.TextStyle{Bold: true}
			}
		},
	)

	tree.OnSelected = func(id string) {
		if id == "passwords.txt" {
			e.UpdateToText("복호화된 비밀번호 리스트...\nNaver: ****\nGoogle: ****")
		} else if id == "cloud.png" {
			var i Icons.Icons
			img, _ := i.Cloud_png()
			// 실제로는 복호화된 []byte를 넘깁니다.
			e.UpdateToImage(img, "png")
		} else if id == "aes.webp" {
			var i Icons.Icons
			img, _ := i.Aes_webp()
			// 실제로는 복호화된 []byte를 넘깁니다.
			e.UpdateToImage(img, "webp")
		}
	}

	// --- [3. 중앙 영역] ---
	e.ContentArea = container.NewStack(widget.NewLabelWithStyle("파일을 선택하세요.", fyne.TextAlignCenter, fyne.TextStyle{Italic: true}))

	// --- [4. 하단 세션 바] ---
	sessionLabel := widget.NewLabel("Algo: " + info.KeyAlgo + " | Vault: " + info.VaultPath)
	logoutBtn := widget.NewButtonWithIcon("Logout", theme.LogoutIcon(), func() {
		e.Window.Close()
		// 여기서 다시 로그인 창을 띄우는 로직을 호출할 수 있습니다.
	})
	logoutBtn.Importance = widget.DangerImportance
	bottomBar := container.NewBorder(nil, nil, sessionLabel, logoutBtn)

	// 레이아웃 결합
	split := container.NewHSplit(tree, e.ContentArea)
	split.Offset = 0.3

	mainLayout := container.NewBorder(toolbar, bottomBar, nil, nil, split)
	e.Window.SetContent(mainLayout)
	e.Window.Resize(fyne.NewSize(1000, 650))
	e.Window.CenterOnScreen()
	e.Window.Show()
}

func (e *MainExplorer) UpdateToText(text string) {
	entry := widget.NewMultiLineEntry()
	entry.SetText(text)
	e.ContentArea.Objects = []fyne.CanvasObject{entry}
	e.ContentArea.Refresh()
}

func (e *MainExplorer) UpdateToImage(data []byte, extension string) {
	// 확장자 힌트를 포함하여 리더 생성 (예: "preview.webp", "preview.png")
	img := canvas.NewImageFromReader(bytes.NewReader(data), "view."+extension)
	img.FillMode = canvas.ImageFillContain

	e.ContentArea.Objects = []fyne.CanvasObject{img}
	e.ContentArea.Refresh()
}
