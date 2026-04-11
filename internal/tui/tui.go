package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/you/bezosbuster/internal/orchestrator"
)

type tab int

const (
	tabAccounts tab = iota
	tabModules
	tabLogs
	numTabs
)

var tabNames = []string{"Accounts", "Modules", "Logs"}

type moduleKey struct{ account, module string }

type Model struct {
	tab      tab
	accounts map[string]string              // account -> status summary
	modules  map[moduleKey]string           // per-cell status
	accOrder []string
	modOrder []string
	logs     []string
	events   <-chan orchestrator.Event
	done     bool
	err      error
}

type eventMsg orchestrator.Event
type doneMsg struct{ err error }
type tickMsg struct{}

func New(events <-chan orchestrator.Event) Model {
	return Model{
		tab:      tabAccounts,
		accounts: map[string]string{},
		modules:  map[moduleKey]string{},
		events:   events,
	}
}

func (m Model) Init() tea.Cmd {
	return waitForEvent(m.events)
}

func waitForEvent(events <-chan orchestrator.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-events
		if !ok {
			return doneMsg{}
		}
		return eventMsg(ev)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab", "right":
			m.tab = (m.tab + 1) % numTabs
		case "shift+tab", "left":
			m.tab = (m.tab + numTabs - 1) % numTabs
		}
	case eventMsg:
		ev := orchestrator.Event(msg)
		if _, ok := m.accounts[ev.AccountID]; !ok {
			m.accOrder = append(m.accOrder, ev.AccountID)
		}
		m.accounts[ev.AccountID] = ev.Status
		k := moduleKey{ev.AccountID, ev.Module}
		if _, ok := m.modules[k]; !ok {
			m.modOrder = appendUnique(m.modOrder, ev.Module)
		}
		m.modules[k] = ev.Status
		line := fmt.Sprintf("[%s] %s/%s → %s", ev.Status, ev.AccountID, ev.Module, ev.Err)
		m.logs = append(m.logs, line)
		if len(m.logs) > 500 {
			m.logs = m.logs[len(m.logs)-500:]
		}
		return m, waitForEvent(m.events)
	case doneMsg:
		m.done = true
		return m, tea.Quit
	}
	return m, nil
}

func appendUnique(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

var (
	header    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Padding(0, 1)
	activeTab = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Underline(true).Padding(0, 1)
	dim       = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

func (m Model) View() string {
	var tabs []string
	for i, name := range tabNames {
		if tab(i) == m.tab {
			tabs = append(tabs, activeTab.Render(name))
		} else {
			tabs = append(tabs, header.Render(name))
		}
	}
	var body string
	switch m.tab {
	case tabAccounts:
		body = m.renderAccounts()
	case tabModules:
		body = m.renderModules()
	case tabLogs:
		body = m.renderLogs()
	}
	footer := dim.Render("tab/shift-tab: switch • q: quit")
	return strings.Join([]string{
		header.Render("BezosBuster"),
		strings.Join(tabs, "  "),
		"",
		body,
		"",
		footer,
	}, "\n")
}

func (m Model) renderAccounts() string {
	if len(m.accOrder) == 0 {
		return dim.Render("waiting…")
	}
	var b strings.Builder
	accs := append([]string(nil), m.accOrder...)
	sort.Strings(accs)
	for _, a := range accs {
		fmt.Fprintf(&b, "%-14s %s\n", a, m.accounts[a])
	}
	return b.String()
}

func (m Model) renderModules() string {
	if len(m.modOrder) == 0 {
		return dim.Render("waiting…")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-20s", "module")
	accs := append([]string(nil), m.accOrder...)
	sort.Strings(accs)
	for _, a := range accs {
		fmt.Fprintf(&b, " %-14s", a)
	}
	b.WriteString("\n")
	mods := append([]string(nil), m.modOrder...)
	sort.Strings(mods)
	for _, mod := range mods {
		fmt.Fprintf(&b, "%-20s", mod)
		for _, a := range accs {
			status := m.modules[moduleKey{a, mod}]
			if status == "" {
				status = "-"
			}
			fmt.Fprintf(&b, " %-14s", status)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (m Model) renderLogs() string {
	if len(m.logs) == 0 {
		return dim.Render("no events yet")
	}
	start := 0
	if len(m.logs) > 30 {
		start = len(m.logs) - 30
	}
	return strings.Join(m.logs[start:], "\n")
}
