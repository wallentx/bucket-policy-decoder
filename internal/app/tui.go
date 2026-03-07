package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/example/bucket-policy-decoder/internal/policy"
	"golang.org/x/term"
)

type lineRange struct {
	Start int
	End   int
}

type policyJSONView struct {
	Lines           []string
	StatementRanges []lineRange
}

type paneRow struct {
	Selected bool
	Text     string
}

type tuiDocument struct {
	Document analyzedDocument
	JSONView policyJSONView
}

type tuiMode string

const (
	tuiModeView tuiMode = "view"
	tuiModeEdit tuiMode = "edit"
)

type tuiInputEvent struct {
	Kind string
	Text string
}

type tuiModel struct {
	Documents        []tuiDocument
	SelectedDocument int
	SelectedStmt     []int
	Color            bool
	Mode             tuiMode
	Draft            []rune
	DraftCursor      int
	DraftStatus      string
	DraftStatusTitle string
	DraftStatusError bool
	ValidationFailed bool
}

const (
	defaultTUIWidth  = 80
	defaultTUIHeight = 24
	minTUIWidth      = 60
	minTUIHeight     = 16
)

var ansiCSIRegexp = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

func supportsTUI(stdin io.Reader, stdout io.Writer) bool {
	if os.Getenv("BUCKET_POLICY_DECODER_NO_TUI") != "" {
		return false
	}
	if os.Getenv("CODEX_CI") != "" && os.Getenv("BUCKET_POLICY_DECODER_FORCE_TUI") == "" {
		return false
	}
	if os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" {
		return false
	}

	inFile, inOK := stdin.(*os.File)
	outFile, outOK := stdout.(*os.File)
	if !inOK || !outOK {
		return false
	}
	inFD, err := fileDescriptor(inFile)
	if err != nil {
		return false
	}
	outFD, err := fileDescriptor(outFile)
	if err != nil {
		return false
	}
	return term.IsTerminal(inFD) && term.IsTerminal(outFD)
}

func runTUI(documents []analyzedDocument, stdin io.Reader, stdout io.Writer, color bool) error {
	model, err := newTUIModel(documents, color)
	if err != nil {
		return err
	}
	_, err = runTUISession(model, stdin, stdout)
	return err
}

func runEditorTUI(stdin io.Reader, stdout io.Writer, color bool) (bool, error) {
	model := newEditorTUIModel(color)
	result, err := runTUISession(model, stdin, stdout)
	if err != nil {
		return false, err
	}
	return result.ValidationFailed, nil
}

func runTUISession(model tuiModel, stdin io.Reader, stdout io.Writer) (tuiModel, error) {
	inFile := stdin.(*os.File)
	outFile := stdout.(*os.File)

	inFD, err := fileDescriptor(inFile)
	if err != nil {
		return model, err
	}
	outFD, err := fileDescriptor(outFile)
	if err != nil {
		return model, err
	}

	state, err := term.MakeRaw(inFD)
	if err != nil {
		return model, fmt.Errorf("enable terminal UI: %w", err)
	}
	defer func() {
		_ = term.Restore(inFD, state)
	}()

	_, _ = fmt.Fprint(outFile, "\x1b[?1049h\x1b[?25l")
	defer func() {
		_, _ = fmt.Fprint(outFile, "\x1b[?25h\x1b[?1049l")
	}()

	reader := bufio.NewReader(inFile)
	for {
		_, _ = fmt.Fprint(outFile, "\x1b[H\x1b[2J")
		width, height := currentTUISize(outFD)
		_, _ = fmt.Fprint(outFile, normalizeTUILineEndings(renderTUIView(model, width, height)))

		event, err := readTUIEvent(reader)
		if err != nil {
			if err == io.EOF {
				return model, nil
			}
			return model, fmt.Errorf("read terminal input: %w", err)
		}

		if shouldQuitTUI(model, event) {
			return model, nil
		}
		switch model.Mode {
		case tuiModeEdit:
			model.handleEditEvent(event)
		default:
			model.handleViewEvent(event)
		}
	}
}

func currentTUISize(fd int) (int, int) {
	width, height, err := term.GetSize(fd)
	if err != nil {
		return defaultTUIWidth, defaultTUIHeight
	}
	if width < minTUIWidth {
		width = minTUIWidth
	}
	if height < minTUIHeight {
		height = minTUIHeight
	}
	return width, height
}

func normalizeTUILineEndings(value string) string {
	return strings.ReplaceAll(value, "\n", "\r\n")
}

func fileDescriptor(file *os.File) (int, error) {
	if file == nil {
		return 0, errors.New("terminal I/O is unavailable")
	}

	fd := file.Fd()
	maxInt := ^uint(0) >> 1
	if fd > uintptr(maxInt) {
		return 0, errors.New("terminal file descriptor is out of range")
	}

	// #nosec G115 -- fd is range-checked against maxInt just above.
	return int(fd), nil
}

func newTUIModel(documents []analyzedDocument, color bool) (tuiModel, error) {
	model := tuiModel{
		Documents:    make([]tuiDocument, 0, len(documents)),
		SelectedStmt: make([]int, len(documents)),
		Color:        color,
		Mode:         tuiModeView,
	}

	for _, document := range documents {
		model.Documents = append(model.Documents, tuiDocument{
			Document: document,
			JSONView: buildPolicyJSONView(document),
		})
	}

	return model, nil
}

func newEditorTUIModel(color bool) tuiModel {
	return tuiModel{
		Color:            color,
		Mode:             tuiModeEdit,
		DraftStatusTitle: " editor ",
		DraftStatus:      "Type or paste a bucket policy JSON document in the top pane, then press Ctrl+S to decode it.",
	}
}

func (m *tuiModel) moveStatement(delta int) {
	if len(m.Documents) == 0 || len(m.SelectedStmt) == 0 {
		return
	}
	index := m.SelectedDocument
	current := m.SelectedStmt[index]
	limit := len(m.Documents[index].Document.Parsed.Statement) - 1
	current += delta
	if current < 0 {
		current = 0
	}
	if current > limit {
		current = limit
	}
	m.SelectedStmt[index] = current
}

func (m *tuiModel) moveDocument(delta int) {
	count := len(m.Documents)
	if count == 0 {
		return
	}
	next := m.SelectedDocument + delta
	if next < 0 {
		next = count - 1
	}
	if next >= count {
		next = 0
	}
	m.SelectedDocument = next
}

func (m *tuiModel) handleViewEvent(event tuiInputEvent) {
	switch event.Kind {
	case "up":
		m.moveStatement(-1)
	case "down":
		m.moveStatement(1)
	case "left":
		m.moveDocument(-1)
	case "right":
		m.moveDocument(1)
	}
}

func (m *tuiModel) handleEditEvent(event tuiInputEvent) {
	switch event.Kind {
	case "save":
		m.decodeDraft()
	case "insert", "literal":
		m.insertDraftText(event.Text)
	case "backspace":
		m.deleteDraftBackward()
	case "left":
		m.moveDraftCursorHorizontal(-1)
	case "right":
		m.moveDraftCursorHorizontal(1)
	case "up":
		m.moveDraftCursorVertical(-1)
	case "down":
		m.moveDraftCursorVertical(1)
	}
}

func shouldQuitTUI(model tuiModel, event tuiInputEvent) bool {
	switch event.Kind {
	case "quit":
		return true
	case "literal":
		return model.Mode == tuiModeView && strings.EqualFold(event.Text, "q")
	default:
		return false
	}
}

func (m tuiModel) currentDocument() tuiDocument {
	if len(m.Documents) == 0 {
		return tuiDocument{}
	}
	return m.Documents[m.SelectedDocument]
}

func (m tuiModel) currentStatementIndex() int {
	if len(m.SelectedStmt) == 0 || m.SelectedDocument >= len(m.SelectedStmt) {
		return 0
	}
	return m.SelectedStmt[m.SelectedDocument]
}

func renderTUIView(model tuiModel, width, height int) string {
	if height < 10 {
		height = 10
	}

	header := renderTUIHeader(model, width)
	remainingHeight := height - 1
	topHeight := remainingHeight * 2 / 3
	bottomHeight := remainingHeight - topHeight
	if topHeight < 6 {
		topHeight = 6
		bottomHeight = remainingHeight - topHeight
	}
	if bottomHeight < 5 {
		bottomHeight = 5
	}

	if model.Mode == tuiModeEdit {
		policyPane := renderDraftPane(model, width, topHeight)
		detailPane := renderDraftStatusPane(model, width, bottomHeight)

		var b strings.Builder
		b.WriteString(header)
		b.WriteByte('\n')
		b.WriteString(renderPanel(" interactive input ", policyPane, width, topHeight, 0))
		b.WriteByte('\n')
		b.WriteString(renderPanel(model.draftStatusTitle(), detailPane, width, bottomHeight, 1))
		return b.String()
	}

	document := model.currentDocument()
	statementIndex := model.currentStatementIndex()
	policyPane := renderPolicyPane(document, statementIndex, width, topHeight, model.Color)
	detailTitle := detailPaneTitle(document, statementIndex)
	detailPane := renderDetailPane(document, statementIndex, width, bottomHeight, model.Color)

	var b strings.Builder
	b.WriteString(header)
	b.WriteByte('\n')
	b.WriteString(renderPanel(document.Document.Input.Name, policyPane, width, topHeight, 0))
	b.WriteByte('\n')
	b.WriteString(renderPanel(detailTitle, detailPane, width, bottomHeight, 1))
	return b.String()
}

func renderTUIHeader(model tuiModel, width int) string {
	if model.Mode == tuiModeEdit {
		header := " edit mode | type or paste policy JSON | Ctrl+S decode | Ctrl+C quit "
		return styleHeader(fitPlain(header, width), model.Color)
	}

	document := model.currentDocument()
	statementIndex := model.currentStatementIndex()
	totalStatements := len(document.Document.Parsed.Statement)

	parts := []string{
		fmt.Sprintf("statement %d/%d", statementIndex+1, totalStatements),
		"↑/↓ statement",
		"q quit",
	}
	if len(model.Documents) > 1 {
		parts = append(parts, fmt.Sprintf("source %d/%d", model.SelectedDocument+1, len(model.Documents)), "←/→ source")
	}

	header := " " + strings.Join(parts, " | ") + " "
	return styleHeader(fitPlain(header, width), model.Color)
}

func (m tuiModel) draftStatusTitle() string {
	if strings.TrimSpace(m.DraftStatusTitle) != "" {
		return m.DraftStatusTitle
	}
	return " editor "
}

func renderPolicyPane(document tuiDocument, statementIndex, width, height int, color bool) []string {
	rangeForStatement := document.JSONView.StatementRanges[statementIndex]
	contentHeight := height - 2
	contentWidth := width - 2
	gutterWidth := 2
	rows, wrappedRange := buildPolicyRows(document.JSONView, rangeForStatement, contentWidth-gutterWidth)
	start := scrollStartForRange(len(rows), contentHeight, wrappedRange)

	lines := make([]string, 0, contentHeight)
	for lineIndex := 0; lineIndex < contentHeight; lineIndex++ {
		sourceIndex := start + lineIndex
		line := ""
		if sourceIndex < len(rows) {
			selected := rows[sourceIndex].Selected
			plain := fitPlain(rows[sourceIndex].Text, contentWidth-gutterWidth)
			plain = padRight(plain, contentWidth-gutterWidth)
			styled := styleJSONLine(plain, color)
			if selected {
				styled = styleSelectedJSONLine(styled, color)
			}
			line = selectedLinePrefix(selected, color) + styled
		}
		lines = append(lines, line)
	}
	return lines
}

func detailPaneTitle(document tuiDocument, statementIndex int) string {
	stmt := document.Document.Parsed.Statement[statementIndex]
	if stmt.SID != "" {
		return fmt.Sprintf(" %s ", stmt.SID)
	}
	return fmt.Sprintf(" statement %d/%d ", statementIndex+1, len(document.Document.Parsed.Statement))
}

func renderDetailPane(document tuiDocument, statementIndex, width, height int, color bool) []string {
	stmt := document.Document.Parsed.Statement[statementIndex]
	lines := []string{}
	lines = append(lines, policy.RenderStatementPlainEnglishWithOptions(stmt, policy.RenderOptions{
		Color: color,
	}))

	findings := findingsForStatement(document.Document.Validation, statementIndex)
	if len(findings) > 0 {
		lines = append(lines, "", "Issues:")
		for _, finding := range findings {
			lines = append(lines, fmt.Sprintf("- %s %s: %s", finding.Severity, finding.Path, finding.Message))
		}
	}

	return wrapLines(lines, width-3, height-2)
}

func renderDraftPane(model tuiModel, width, height int) []string {
	contentHeight := height - 2
	contentWidth := width - 2
	rows, cursorRow := buildDraftRows(model.Draft, model.DraftCursor, contentWidth)
	start := scrollStartForCursor(len(rows), contentHeight, cursorRow)

	lines := make([]string, 0, contentHeight)
	for lineIndex := 0; lineIndex < contentHeight; lineIndex++ {
		sourceIndex := start + lineIndex
		line := ""
		if sourceIndex < len(rows) {
			line = padRight(styleDraftLine(rows[sourceIndex], model.Color), contentWidth)
		}
		lines = append(lines, line)
	}
	return lines
}

func renderDraftStatusPane(model tuiModel, width, height int) []string {
	lines := []string{}
	if strings.TrimSpace(model.DraftStatus) != "" {
		lines = append(lines, model.DraftStatus)
	}
	if len(model.Draft) == 0 {
		lines = append(lines, "", "Example:", `{`, `  "Version": "2012-10-17",`, `  "Statement": []`, `}`)
	}
	return wrapLines(lines, width-3, height-2)
}

func buildDraftRows(draft []rune, cursor, width int) ([]string, int) {
	if width < 1 {
		width = 1
	}

	const cursorGlyph = '\u258f'

	display := make([]rune, 0, len(draft)+1)
	for index, r := range draft {
		if index == cursor {
			display = append(display, cursorGlyph)
		}
		display = append(display, r)
	}
	if cursor >= len(draft) {
		display = append(display, cursorGlyph)
	}

	logicalLines := strings.Split(string(display), "\n")
	rows := make([]string, 0, len(logicalLines))
	cursorRow := 0

	for _, logicalLine := range logicalLines {
		segments := wrapPlainLine(normalizeDraftDisplayLine(logicalLine), width)
		if len(segments) == 0 {
			segments = []string{""}
		}
		for _, segment := range segments {
			if strings.ContainsRune(segment, cursorGlyph) {
				cursorRow = len(rows)
			}
			rows = append(rows, segment)
		}
	}

	if len(rows) == 0 {
		return []string{string(cursorGlyph)}, 0
	}
	return rows, cursorRow
}

func styleDraftLine(value string, color bool) string {
	const cursor = "\u258f"
	if !strings.Contains(value, cursor) {
		return value
	}
	if !color {
		return strings.ReplaceAll(value, cursor, "|")
	}
	return strings.ReplaceAll(value, cursor, "\x1b[30;47m \x1b[0m")
}

func normalizeDraftDisplayLine(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	if !strings.Contains(value, "\t") {
		return value
	}

	var b strings.Builder
	column := 0
	for _, r := range value {
		if r != '\t' {
			b.WriteRune(r)
			column++
			continue
		}

		spaces := 4 - (column % 4)
		if spaces == 0 {
			spaces = 4
		}
		b.WriteString(strings.Repeat(" ", spaces))
		column += spaces
	}
	return b.String()
}

func scrollStartForCursor(totalLines, height, cursorRow int) int {
	if totalLines <= height || height <= 0 {
		return 0
	}
	if cursorRow <= height/3 {
		return 0
	}
	start := cursorRow - height/3
	maxStart := totalLines - height
	if start > maxStart {
		return maxStart
	}
	return start
}

func (m *tuiModel) insertDraftText(text string) {
	if text == "" {
		return
	}

	insert := []rune(text)
	next := make([]rune, 0, len(m.Draft)+len(insert))
	next = append(next, m.Draft[:m.DraftCursor]...)
	next = append(next, insert...)
	next = append(next, m.Draft[m.DraftCursor:]...)
	m.Draft = next
	m.DraftCursor += len(insert)
	if m.DraftStatusError {
		m.DraftStatus = ""
		m.DraftStatusTitle = " editor "
		m.DraftStatusError = false
	}
}

func (m *tuiModel) deleteDraftBackward() {
	if m.DraftCursor == 0 || len(m.Draft) == 0 {
		return
	}

	m.Draft = append(m.Draft[:m.DraftCursor-1], m.Draft[m.DraftCursor:]...)
	m.DraftCursor--
}

func (m *tuiModel) moveDraftCursorHorizontal(delta int) {
	next := m.DraftCursor + delta
	if next < 0 {
		next = 0
	}
	if next > len(m.Draft) {
		next = len(m.Draft)
	}
	m.DraftCursor = next
}

func (m *tuiModel) moveDraftCursorVertical(delta int) {
	lineStart, column := draftCursorLineStartAndColumn(m.Draft, m.DraftCursor)
	if delta < 0 {
		if lineStart == 0 {
			return
		}
		prevEnd := lineStart - 1
		prevStart := previousLineStart(m.Draft, prevEnd)
		m.DraftCursor = prevStart + minInt(column, prevEnd-prevStart)
		return
	}

	lineEnd := nextLineBoundary(m.Draft, lineStart)
	if lineEnd >= len(m.Draft) {
		return
	}
	nextStart := lineEnd + 1
	nextEnd := nextLineBoundary(m.Draft, nextStart)
	m.DraftCursor = nextStart + minInt(column, nextEnd-nextStart)
}

func (m *tuiModel) decodeDraft() {
	raw := []byte(string(m.Draft))
	documents, validationFailed, err := analyzeInputs([]inputDocument{{
		Name: "interactive input",
		Raw:  raw,
	}})
	if err != nil {
		m.DraftStatusTitle = " decode error "
		m.DraftStatus = err.Error()
		m.DraftStatusError = true
		return
	}

	viewModel, err := newTUIModel(documents, m.Color)
	if err != nil {
		m.DraftStatusTitle = " decode error "
		m.DraftStatus = err.Error()
		m.DraftStatusError = true
		return
	}

	m.Documents = viewModel.Documents
	m.SelectedDocument = 0
	m.SelectedStmt = viewModel.SelectedStmt
	m.Mode = tuiModeView
	m.ValidationFailed = validationFailed
}

func draftCursorLineStartAndColumn(draft []rune, cursor int) (int, int) {
	start := 0
	for index := cursor - 1; index >= 0; index-- {
		if draft[index] == '\n' {
			start = index + 1
			break
		}
	}
	return start, cursor - start
}

func previousLineStart(draft []rune, end int) int {
	start := 0
	for index := end - 1; index >= 0; index-- {
		if draft[index] == '\n' {
			start = index + 1
			break
		}
	}
	return start
}

func nextLineBoundary(draft []rune, start int) int {
	for index := start; index < len(draft); index++ {
		if draft[index] == '\n' {
			return index
		}
	}
	return len(draft)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func findingsForStatement(validation policy.ValidationResult, statementIndex int) []policy.Finding {
	prefix := fmt.Sprintf("Statement[%d]", statementIndex)
	findings := make([]policy.Finding, 0, len(validation.Findings))

	for _, finding := range validation.Findings {
		switch {
		case strings.HasPrefix(finding.Path, prefix):
			findings = append(findings, finding)
		case !strings.HasPrefix(finding.Path, "Statement["):
			findings = append(findings, finding)
		}
	}

	return findings
}

func buildPolicyJSONView(document analyzedDocument) policyJSONView {
	pretty, err := indentJSON(document.Input.Raw, "", "  ")
	if err == nil {
		rawStatements, singleObject, rawErr := extractStatementRawMessages(document.Input.Raw)
		if rawErr == nil {
			ranges, rangeErr := locateStatementRanges(pretty, rawStatements, singleObject)
			if rangeErr == nil && len(ranges) == len(document.Parsed.Statement) {
				return policyJSONView{
					Lines:           strings.Split(pretty, "\n"),
					StatementRanges: ranges,
				}
			}
		}
	}

	return buildFallbackPolicyJSONView(document.Parsed)
}

func buildFallbackPolicyJSONView(p policy.Policy) policyJSONView {
	lines := make([]string, 0, len(p.Statement)*8+6)
	lines = append(lines, "{")

	if p.Version != "" {
		lines = append(lines, fmt.Sprintf(`  "Version": %q,`, p.Version))
	}
	if p.ID != "" {
		lines = append(lines, fmt.Sprintf(`  "Id": %q,`, p.ID))
	}
	lines = append(lines, `  "Statement": [`)

	ranges := make([]lineRange, 0, len(p.Statement))
	for index, stmt := range p.Statement {
		raw, err := json.MarshalIndent(statementForDisplay(stmt), "    ", "  ")
		if err != nil {
			raw = []byte(`    {"error": "failed to render statement"}`)
		}
		statementLines := strings.Split(string(raw), "\n")
		if index < len(p.Statement)-1 {
			statementLines[len(statementLines)-1] += ","
		}
		ranges = append(ranges, lineRange{
			Start: len(lines),
			End:   len(lines) + len(statementLines) - 1,
		})
		lines = append(lines, statementLines...)
	}

	lines = append(lines, "  ]", "}")
	return policyJSONView{
		Lines:           lines,
		StatementRanges: ranges,
	}
}

func statementForDisplay(stmt policy.Statement) map[string]any {
	body := make(map[string]any)
	if stmt.SID != "" {
		body["Sid"] = stmt.SID
	}
	if stmt.Effect != "" {
		body["Effect"] = stmt.Effect
	}
	if principal := principalForDisplay(stmt.Principal); principal != nil {
		body["Principal"] = principal
	}
	if principal := principalForDisplay(stmt.NotPrincipal); principal != nil {
		body["NotPrincipal"] = principal
	}
	if action := stringListForDisplay(stmt.Action); action != nil {
		body["Action"] = action
	}
	if action := stringListForDisplay(stmt.NotAction); action != nil {
		body["NotAction"] = action
	}
	if resource := stringListForDisplay(stmt.Resource); resource != nil {
		body["Resource"] = resource
	}
	if resource := stringListForDisplay(stmt.NotResource); resource != nil {
		body["NotResource"] = resource
	}
	if condition := conditionsForDisplay(stmt.Condition); condition != nil {
		body["Condition"] = condition
	}
	return body
}

func principalForDisplay(value policy.PrincipalValue) any {
	if value.Any {
		return "*"
	}
	if len(value.Values) == 0 {
		return nil
	}

	body := make(map[string]any, len(value.Values))
	for _, key := range policyKeys(value.Values) {
		body[key] = stringListForDisplay(value.Values[key])
	}
	return body
}

func conditionsForDisplay(conditions policy.Conditions) map[string]any {
	if len(conditions) == 0 {
		return nil
	}

	body := make(map[string]any, len(conditions))
	for _, operator := range policyKeys(conditions) {
		entries := make(map[string]any, len(conditions[operator]))
		for _, key := range policyKeys(conditions[operator]) {
			entries[key] = stringListForDisplay(conditions[operator][key])
		}
		body[operator] = entries
	}
	return body
}

func stringListForDisplay(values []string) any {
	switch len(values) {
	case 0:
		return nil
	case 1:
		return values[0]
	default:
		out := make([]string, len(values))
		copy(out, values)
		return out
	}
}

func policyKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func buildPolicyRows(view policyJSONView, selectedRange lineRange, wrapWidth int) ([]paneRow, lineRange) {
	rows := make([]paneRow, 0, len(view.Lines))
	wrappedRange := lineRange{Start: -1, End: -1}

	for index, line := range view.Lines {
		selected := index >= selectedRange.Start && index <= selectedRange.End
		segments := wrapPlainLine(line, wrapWidth)
		start := len(rows)
		for _, segment := range segments {
			rows = append(rows, paneRow{
				Selected: selected,
				Text:     segment,
			})
		}
		end := len(rows) - 1
		if selected {
			if wrappedRange.Start == -1 {
				wrappedRange.Start = start
			}
			wrappedRange.End = end
		}
	}

	if wrappedRange.Start == -1 {
		wrappedRange = lineRange{Start: 0, End: 0}
	}
	return rows, wrappedRange
}

func renderPanel(title string, lines []string, width, height int, leftPadding int) string {
	if width < 4 {
		width = 4
	}
	if height < 3 {
		height = 3
	}
	if leftPadding < 0 {
		leftPadding = 0
	}

	contentHeight := height - 2
	contentWidth := width - 2
	textWidth := contentWidth - leftPadding
	if textWidth < 1 {
		textWidth = 1
	}
	title = " " + strings.TrimSpace(title) + " "
	if visibleWidth(title) > contentWidth {
		title = fitPlain(title, contentWidth)
	}

	var b strings.Builder
	b.WriteString("╭")
	b.WriteString(title)
	b.WriteString(strings.Repeat("─", contentWidth-visibleWidth(title)))
	b.WriteString("╮\n")

	for index := 0; index < contentHeight; index++ {
		line := strings.Repeat(" ", leftPadding) + padRight("", textWidth)
		if index > 0 {
			contentIndex := index - 1
			if contentIndex < len(lines) {
				line = strings.Repeat(" ", leftPadding) + padRight(trimANSIToWidth(lines[contentIndex], textWidth), textWidth)
			}
		}
		b.WriteString("│")
		b.WriteString(line)
		b.WriteString("│\n")
	}

	b.WriteString("╰")
	b.WriteString(strings.Repeat("─", contentWidth))
	b.WriteString("╯")
	return b.String()
}

func scrollStartForRange(totalLines, height int, focus lineRange) int {
	if totalLines <= height || height <= 0 {
		return 0
	}
	if focus.Start <= height/3 {
		return 0
	}
	start := focus.Start - 2
	if start < 0 {
		return 0
	}
	maxStart := totalLines - height
	if start > maxStart {
		return maxStart
	}
	return start
}

func wrapLines(lines []string, width, height int) []string {
	if width < 4 {
		width = 4
	}
	if height < 1 {
		height = 1
	}

	wrapped := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			wrapped = append(wrapped, "")
			continue
		}
		wrapped = append(wrapped, wrapANSIWords(line, width)...)
	}
	if len(wrapped) > height {
		return wrapped[:height]
	}
	return wrapped
}

func wrapANSIWords(line string, width int) []string {
	words := strings.Fields(line)
	if len(words) == 0 {
		return []string{""}
	}

	lines := make([]string, 0, len(words))
	current := ""
	for _, word := range words {
		if visibleWidth(word) > width {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
			lines = append(lines, fitANSI(word, width))
			continue
		}

		candidate := word
		if current != "" {
			candidate = current + " " + word
		}
		if visibleWidth(candidate) <= width {
			current = candidate
			continue
		}

		lines = append(lines, current)
		current = word
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func fitANSI(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if visibleWidth(value) <= width {
		return value
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}

	runes := []rune(stripANSI(value))
	trimmed := string(runes[:width-3]) + "..."
	prefix := leadingANSI(value)
	suffix := trailingReset(value)
	if prefix == "" && suffix == "" {
		return trimmed
	}
	return prefix + trimmed + suffix
}

func trimANSIToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if visibleWidth(value) <= width {
		return value
	}

	var b strings.Builder
	visible := 0
	activeStyle := false

	for index := 0; index < len(value); {
		if value[index] == 0x1b {
			end := ansiCSIRegexp.FindStringIndex(value[index:])
			if end == nil || end[0] != 0 {
				index++
				continue
			}

			escape := value[index : index+end[1]]
			b.WriteString(escape)
			if strings.HasSuffix(escape, "[0m") {
				activeStyle = false
			} else if strings.HasSuffix(escape, "m") {
				activeStyle = true
			}
			index += end[1]
			continue
		}

		r, size := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && size == 1 {
			index += size
			continue
		}
		if visible >= width {
			break
		}

		b.WriteRune(r)
		visible++
		index += size
	}

	if activeStyle {
		b.WriteString("\x1b[0m")
	}
	return b.String()
}

func leadingANSI(value string) string {
	index := 0
	for index < len(value) && value[index] == 0x1b {
		end := index + 1
		for end < len(value) && (value[end] < '@' || value[end] > '~') {
			end++
		}
		if end >= len(value) {
			break
		}
		end++
		index = end
	}
	return value[:index]
}

func trailingReset(value string) string {
	const reset = "\x1b[0m"
	if strings.HasSuffix(value, reset) {
		return reset
	}
	return ""
}

func readTUIEvent(reader *bufio.Reader) (tuiInputEvent, error) {
	value, err := reader.ReadByte()
	if err != nil {
		return tuiInputEvent{}, err
	}

	switch value {
	case 3:
		return tuiInputEvent{Kind: "quit"}, nil
	case 19:
		return tuiInputEvent{Kind: "save"}, nil
	case 8, 127:
		return tuiInputEvent{Kind: "backspace"}, nil
	case '\r', '\n':
		return tuiInputEvent{Kind: "insert", Text: "\n"}, nil
	case '\t':
		return tuiInputEvent{Kind: "insert", Text: "\t"}, nil
	case 27:
		next, err := reader.ReadByte()
		if err != nil {
			return tuiInputEvent{}, err
		}
		if next != '[' {
			return tuiInputEvent{}, nil
		}
		direction, err := reader.ReadByte()
		if err != nil {
			return tuiInputEvent{}, err
		}
		switch direction {
		case 'A':
			return tuiInputEvent{Kind: "up"}, nil
		case 'B':
			return tuiInputEvent{Kind: "down"}, nil
		case 'C':
			return tuiInputEvent{Kind: "right"}, nil
		case 'D':
			return tuiInputEvent{Kind: "left"}, nil
		default:
			return tuiInputEvent{}, nil
		}
	default:
		if value < utf8.RuneSelf {
			if value < 0x20 {
				return tuiInputEvent{}, nil
			}
			return tuiInputEvent{Kind: "literal", Text: string(rune(value))}, nil
		}
		if err := reader.UnreadByte(); err != nil {
			return tuiInputEvent{}, err
		}
		r, _, err := reader.ReadRune()
		if err != nil {
			return tuiInputEvent{}, err
		}
		return tuiInputEvent{Kind: "literal", Text: string(r)}, nil
	}
}

func wrapPlainLine(value string, width int) []string {
	if width < 1 {
		return []string{""}
	}

	runes := []rune(value)
	if len(runes) == 0 {
		return []string{""}
	}

	lines := make([]string, 0, len(runes)/width+1)
	for len(runes) > width {
		lines = append(lines, string(runes[:width]))
		runes = runes[width:]
	}
	lines = append(lines, string(runes))
	return lines
}

func fitPlain(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if visibleWidth(value) <= width {
		return value
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}
	return trimToWidth(value, width-3) + "..."
}

func trimToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	var b strings.Builder
	count := 0
	for _, r := range value {
		if count >= width {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

func padRight(value string, width int) string {
	if width <= 0 {
		return ""
	}
	padding := width - visibleWidth(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func visibleWidth(value string) int {
	return utf8.RuneCountInString(stripANSI(value))
}

func stripANSI(value string) string {
	return ansiCSIRegexp.ReplaceAllString(value, "")
}

func styleHeader(value string, color bool) string {
	if !color {
		return value
	}
	return "\x1b[1;30;47m" + padRight(value, visibleWidth(value)) + "\x1b[0m"
}

func selectedLinePrefix(selected, color bool) string {
	if !selected {
		return "  "
	}
	if !color {
		return "> "
	}
	return "\x1b[38;5;81m▌\x1b[0m "
}

func styleSelectedJSONLine(value string, color bool) string {
	if !color || value == "" {
		return value
	}

	const (
		background = "\x1b[48;5;236m"
		reset      = "\x1b[0m"
		reapply    = "\x1b[0;48;5;236m"
	)

	return background + strings.ReplaceAll(value, reset, reapply) + reset
}

func styleJSONLine(value string, color bool) string {
	if !color || value == "" {
		return value
	}

	var b strings.Builder
	for index := 0; index < len(value); {
		switch value[index] {
		case '"':
			token, next := readJSONString(value, index)
			style := "\x1b[32m"
			if jsonStringLooksLikeKey(value, next) {
				style = "\x1b[1;36m"
			}
			b.WriteString(style)
			b.WriteString(token)
			b.WriteString("\x1b[0m")
			index = next
		case '{', '}', '[', ']', ':', ',':
			b.WriteString("\x1b[38;5;244m")
			b.WriteByte(value[index])
			b.WriteString("\x1b[0m")
			index++
		default:
			token, next := readJSONBareToken(value, index)
			if token == "" {
				b.WriteByte(value[index])
				index++
				continue
			}
			switch {
			case token == "true" || token == "false" || token == "null":
				b.WriteString("\x1b[1;35m")
				b.WriteString(token)
				b.WriteString("\x1b[0m")
			case looksLikeJSONNumber(token):
				b.WriteString("\x1b[1;33m")
				b.WriteString(token)
				b.WriteString("\x1b[0m")
			default:
				b.WriteString(token)
			}
			index = next
		}
	}
	return b.String()
}

func readJSONString(value string, start int) (string, int) {
	index := start + 1
	for index < len(value) {
		if value[index] == '\\' {
			index += 2
			continue
		}
		if value[index] == '"' {
			index++
			break
		}
		index++
	}
	return value[start:index], index
}

func jsonStringLooksLikeKey(value string, next int) bool {
	for next < len(value) && (value[next] == ' ' || value[next] == '\t') {
		next++
	}
	return next < len(value) && value[next] == ':'
}

func readJSONBareToken(value string, start int) (string, int) {
	if start >= len(value) {
		return "", start
	}
	if value[start] == ' ' || value[start] == '\t' {
		end := start
		for end < len(value) && (value[end] == ' ' || value[end] == '\t') {
			end++
		}
		return value[start:end], end
	}
	end := start
	for end < len(value) {
		switch value[end] {
		case ' ', '\t', '{', '}', '[', ']', ':', ',', '"':
			return value[start:end], end
		default:
			end++
		}
	}
	return value[start:end], end
}

func looksLikeJSONNumber(value string) bool {
	if value == "" {
		return false
	}
	digits := 0
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '-', r == '+', r == '.', r == 'e', r == 'E':
		default:
			return false
		}
	}
	return digits > 0
}

func indentJSON(raw []byte, prefix, indent string) (string, error) {
	var b bytes.Buffer
	if err := json.Indent(&b, bytes.TrimSpace(raw), prefix, indent); err != nil {
		return "", err
	}
	return b.String(), nil
}

func extractStatementRawMessages(raw []byte) ([]json.RawMessage, bool, error) {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, err
	}

	statement := bytes.TrimSpace(doc.Statement)
	if len(statement) == 0 {
		return nil, false, errors.New("policy does not contain Statement")
	}

	switch statement[0] {
	case '{':
		return []json.RawMessage{statement}, true, nil
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(statement, &items); err != nil {
			return nil, false, err
		}
		return items, false, nil
	default:
		return nil, false, errors.New("statement must be an object or array")
	}
}

func locateStatementRanges(pretty string, statements []json.RawMessage, singleObject bool) ([]lineRange, error) {
	if singleObject {
		rng, err := locateSingleStatementObjectRange(pretty)
		if err != nil {
			return nil, err
		}
		return []lineRange{rng}, nil
	}

	ranges := make([]lineRange, 0, len(statements))
	searchFrom := 0

	for _, statement := range statements {
		stmtPretty, err := indentJSON(statement, "    ", "  ")
		if err != nil {
			return nil, err
		}
		index := strings.Index(pretty[searchFrom:], stmtPretty)
		if index < 0 {
			return nil, errors.New("failed to locate statement in rendered JSON")
		}

		absoluteIndex := searchFrom + index
		startLine := strings.Count(pretty[:absoluteIndex], "\n")
		endLine := startLine + strings.Count(stmtPretty, "\n")
		ranges = append(ranges, lineRange{Start: startLine, End: endLine})
		searchFrom = absoluteIndex + len(stmtPretty)
	}

	return ranges, nil
}

func locateSingleStatementObjectRange(pretty string) (lineRange, error) {
	keyIndex := strings.Index(pretty, `"Statement": {`)
	if keyIndex < 0 {
		return lineRange{}, errors.New("failed to locate Statement object in rendered JSON")
	}

	objectStart := strings.Index(pretty[keyIndex:], "{")
	if objectStart < 0 {
		return lineRange{}, errors.New("failed to locate Statement object start")
	}
	objectStart += keyIndex

	inString := false
	escaped := false
	depth := 0
	objectEnd := -1

	for index := objectStart; index < len(pretty); index++ {
		ch := pretty[index]
		switch {
		case escaped:
			escaped = false
		case ch == '\\' && inString:
			escaped = true
		case ch == '"':
			inString = !inString
		case inString:
			continue
		case ch == '{':
			depth++
		case ch == '}':
			depth--
			if depth == 0 {
				objectEnd = index
				index = len(pretty)
			}
		}
	}

	if objectEnd < 0 {
		return lineRange{}, errors.New("failed to locate Statement object end")
	}

	startLine := strings.Count(pretty[:keyIndex], "\n")
	endLine := strings.Count(pretty[:objectEnd], "\n")
	return lineRange{Start: startLine, End: endLine}, nil
}
