"""Colour tokens, read by the window and by the HTML report.

    One table for both. Before it existed the Qt sheet carried 86 inline hexes
    (47 distinct shades) and the report's <style> block another 70 (30 distinct),
    so "deepen the outline" meant finding every copy of one shade in two files -
    and the amber and green text shades were each spelled twice, one digit apart
    (#8a5b06 against #8a5c07, #1f7a52 against #1d7a52). The keys are roles, not
    colour names: a shade that reads as a soft pink on a band is a disabled
    button elsewhere. QSS cannot nest and has no
    variables, so each ramp is spelled out - base, hover, pressed, disabled -
    and the report's CSS is a %(...)s template like the sheet.
"""

P = {
    # Ink and text - the line weight of the whole window comes from these
    "deep": "#1f2340",
    "ink": "#2a2e4d",
    "text": "#414a70",
    "text_soft": "#4a5480",
    "mute_strong": "#5b6690",
    "mute": "#6b7597",
    "neutral": "#93a0b5",
    "faint_text": "#aab3c8",

    # Surfaces, lines and the page
    "white": "#ffffff",
    "page": "#e9eff9",
    # The page is a wash, not a flat fill: pink at the top where the mascot is,
    # cool blue at the bottom where the board sits. Nothing measures differently
    # because of it - it is a background brush, not a box.
    "wash_top": "#f7edf5",
    "wash_low": "#e6eef9",
    "surface": "#f5f7fb",
    "line": "#bcccec",
    "line_card": "#c9d9f1",
    "faint_line": "#c9cfdb",
    "glass": "rgba(255, 255, 255, 0.72)",
    "glass_soft": "rgba(255, 255, 255, 0.66)",
    # The report's own surfaces: a written-out file is read on paper and in a
    # browser, so it keeps a whiter sheet and a paler shelf than the window.
    "paper": "#fbfdff",
    "shelf": "#f4f7fd",
    "zebra": "#f8fbff",
    "print_line": "#b9c3d8",

    # Interaction tints
    "hover": "#f2f7ff",
    "band_tint": "#fdeaf2",
    "pressed_tint": "#e2ecff",
    "sel_bg": "#ffd9e7",
    "disable_bg": "#f2f4f8",
    "on_dark": "#f2f5ff",

    # Accent - the pink the mascot leans on
    "accent": "#e0518b",
    "accent_press": "#b83c6a",

    # Primary button ramp
    "btn_top": "#ee6b9d",
    "btn_bottom": "#d64a80",
    "btn_hover_top": "#e75d92",
    "btn_hover_bottom": "#c94476",
    "btn_press": "#bd3c6a",
    "btn_off": "#edc3d5",
    "btn_off_line": "#c0b4c4",
    "btn_off_text": "#fbf2f6",

    # Status - one background, one border, one badge per verdict
    "red_bg": "#fff3f2",
    "red_line": "#f4cfcb",
    "red_tag": "#e2564f",
    "yellow_bg": "#fff8e8",
    "yellow_line": "#f0e0b6",
    "yellow_tag": "#eaa11c",
    "yellow_tag_text": "#3d2a05",
    "green_bg": "#f0f8f3",
    "green_line": "#c9e6d6",
    "green_tag": "#3fa877",
    # Group headings and the report's numbers set these as text, so they take a
    # darker step than the spine and the tag: the bright shades measure 3.2 / 1.9 /
    # 2.6 against the page, these 4.7 / 5.0 / 4.6. The window had a near-duplicate
    # step of its own (#c8362f / #8a5b06 / #1f7a52); one set now, the report's.
    "red_ink": "#c03a34",
    "yellow_ink": "#8a5c07",
    "green_ink": "#1d7a52",
    # Hover deepens the outline only: a card that changed colour as well would
    # read as a new verdict rather than as the one being pointed at.
    "red_line_hover": "#eaa49a",
    "yellow_line_hover": "#e5c287",
    "green_line_hover": "#9ad3b5",
    "gray_line_hover": "#c0cce4",

    # Chips, bar and scroller
    "chip_line": "#9fb3d8",
    "chip_on": "#ffe3ee",
    "bar_top": "#6fc0f2",
    "bar_bottom": "#4aa3e8",
    "track": "#e2ebf8",
    "handle": "#a9bcdd",
    "handle_hover": "#7f9ccd",
    "handle_press": "#6b8bc4",
}

# Cards paint their own drop layer: QSS has no box-shadow and Qt rejects it.
SHADOW = (42, 46, 77, 46)


_TEMPLATE = """
QMainWindow, QWidget#Root {
    background: qlineargradient(x1:0, y1:0, x2:0.25, y2:1,
                                stop:0 %(wash_top)s, stop:0.45 %(page)s,
                                stop:1 %(wash_low)s);
    color: %(text)s;
}
QWidget {
    color: %(text)s;
    selection-background-color: %(sel_bg)s; selection-color: %(ink)s;
}
QScrollArea {
    background: %(glass)s; border: 1px solid %(line)s;
    border-radius: 16px; border-bottom-left-radius: 5px;
}
QScrollArea > QWidget { background: transparent; }
QScrollArea > QWidget > QWidget, QWidget#Board { background: transparent; }

#Title    { font-size: 21px; font-weight: 700; color: %(ink)s; }
#Subtitle { font-size: 14px; color: %(mute)s; }
#Verdict  { font-size: 15px; font-weight: 700; color: %(ink)s;
            padding: 2px 0 0; }
#Progress { font-size: 14px; color: %(mute)s; }

QFrame#Hero {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 %(white)s, stop:1 %(band_tint)s);
    border: 2px solid %(ink)s;
    border-radius: 18px; border-bottom-right-radius: 8px;
}
QLabel#HeroName { font-size: 13px; font-weight: 700; color: %(accent)s; }
QLabel#HeroSay  { font-size: 14px; color: %(ink)s; }

QFrame#Card {
    background: %(surface)s; border: 1px solid %(line_card)s;
    border-radius: 14px; border-bottom-right-radius: 5px;
}
QFrame#Card[status="red"]    { background: %(red_bg)s; border-color: %(red_line)s;
    border-left: 3px solid %(red_tag)s; }
QFrame#Card[status="yellow"] { background: %(yellow_bg)s; border-color: %(yellow_line)s;
    border-left: 3px solid %(yellow_tag)s; }
QFrame#Card[status="green"]  { background: %(green_bg)s; border-color: %(green_line)s;
    border-left: 3px solid %(green_tag)s; }
QFrame#Card[status="gray"]   { background: %(surface)s; border-color: %(line_card)s;
    border-left: 3px solid %(neutral)s; }
/* Hover deepens the outline only. The spine is restated because border-color
   would otherwise repaint it too, and the spine is what says which group a card
   belongs to - it must not change when the pointer arrives. */
QFrame#Card[status="red"]:hover    { border-color: %(red_line_hover)s; border-left: 3px solid %(red_tag)s; }
QFrame#Card[status="yellow"]:hover { border-color: %(yellow_line_hover)s; border-left: 3px solid %(yellow_tag)s; }
QFrame#Card[status="green"]:hover  { border-color: %(green_line_hover)s; border-left: 3px solid %(green_tag)s; }
QFrame#Card[status="gray"]:hover   { border-color: %(gray_line_hover)s; border-left: 3px solid %(neutral)s; }

QLabel#GroupHead {
    font-size: 13px; font-weight: 700; color: %(mute)s;
    background: transparent; padding: 3px 2px 0 8px;
    border-left: 3px solid %(line)s;
}
/* The heading carries the same spine as its cards, so the group reads as one
   object even when the cards of that group are two rows apart. The word itself
   uses a darker step than the spine: the amber shade as text measures 1.9:1
   against the page, which is why the pill is dark ink on amber and not amber
   text. The spine keeps the bright step because it is 3 px of solid colour. */
QLabel#GroupHead[status="red"]    { color: %(red_ink)s; border-left-color: %(red_tag)s; }
QLabel#GroupHead[status="yellow"] { color: %(yellow_ink)s; border-left-color: %(yellow_tag)s; }
QLabel#GroupHead[status="green"]  { color: %(green_ink)s; border-left-color: %(green_tag)s; }
QLabel#GroupHead[status="gray"]   { color: %(mute_strong)s; border-left-color: %(neutral)s; }
QFrame#Bubble { background: transparent; border: none; }

QLabel#Tag {
    font-size: 12px; font-weight: 700; padding: 4px 11px;
    border-radius: 10px; border-bottom-left-radius: 4px;
    background: %(neutral)s; color: %(white)s;
}
QLabel#Tag[status="red"]    { background: %(red_tag)s; color: %(white)s; }
QLabel#Tag[status="yellow"] { background: %(yellow_tag)s; color: %(yellow_tag_text)s; }
QLabel#Tag[status="green"]  { background: %(green_tag)s; color: %(white)s; }
QLabel#Tag[status="gray"]   { background: %(neutral)s; color: %(white)s; }
QLabel#Head  { font-size: 18px; font-weight: 700; color: %(ink)s; }
QLabel#Plain { font-size: 14px; color: %(text)s; }
QLabel#Steps { font-size: 14px; color: %(text_soft)s; }

QTabWidget::pane {
    border: 1px solid %(line_card)s; border-radius: 12px;
    background: %(paper)s; top: -1px;
}
QTabBar::tab {
    font-size: 13px; color: %(mute)s; background: transparent;
    padding: 6px 11px 5px; border: 1px solid %(line_card)s;
    border-bottom: none; border-top-left-radius: 11px;
    border-top-right-radius: 11px;
}
QTabBar::tab:selected {
    color: %(ink)s; font-weight: 700; background: %(paper)s;
}
QTabBar::tab:hover { color: %(ink)s; background: %(hover)s; }

QFrame#Symptom {
    background: %(glass_soft)s; border: 1px solid %(line)s;
    border-radius: 14px; border-bottom-left-radius: 5px;
}
QPushButton#Chip {
    padding: 3px 12px 2px; border: 2px solid %(chip_line)s;
    border-bottom-width: 4px; border-radius: 12px;
    border-bottom-right-radius: 6px;
    background: %(white)s; color: %(text)s; font-weight: 400;
}
QPushButton#Chip:hover   { background: %(hover)s; border-color: %(ink)s; }
QPushButton#Chip:pressed { border-bottom-width: 2px; }
QPushButton#Chip:checked {
    background: %(chip_on)s; border-color: %(accent)s; color: %(ink)s;
    font-weight: 700;
}

QPushButton {
    background: %(white)s; border: 2px solid %(ink)s;
    border-bottom-width: 4px; border-radius: 11px;
    padding: 7px 15px 6px; font-size: 14px; font-weight: 700; color: %(ink)s;
    outline: none;
}
QPushButton:hover    { background: %(hover)s; }
QPushButton:pressed  { background: %(pressed_tint)s; border-bottom-width: 2px;
                       padding: 8px 14px 3px; }
QPushButton:focus    { border-color: %(accent)s; }
QPushButton:disabled { color: %(faint_text)s; background: %(disable_bg)s;
                       border-color: %(faint_line)s; }
QPushButton#Toggle {
    background: transparent; border: none; padding: 2px 0;
    font-size: 13px; font-weight: 700; color: %(mute_strong)s; text-align: left;
}
QPushButton#Toggle:hover   { color: %(accent)s; background: transparent;
                             border: none; }
QPushButton#Toggle:pressed { color: %(accent_press)s; background: transparent;
                             border: none; }
QPushButton#Primary {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 %(btn_top)s, stop:1 %(btn_bottom)s);
    border: 2px solid %(ink)s; border-bottom-width: 6px; color: %(white)s;
    font-size: 19px; font-weight: 700; padding: 11px 26px 8px;
    border-radius: 14px; border-bottom-left-radius: 6px;
}
QPushButton#Primary:hover   { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 %(btn_hover_top)s, stop:1 %(btn_hover_bottom)s); border-color: %(ink)s; }
QPushButton#Primary:pressed { background: %(btn_press)s; border-bottom-width: 3px;
                              padding: 14px 26px 5px; border-color: %(deep)s; }
QPushButton#Primary:focus   { border-color: %(accent)s; }
QPushButton#Primary:disabled { background: %(btn_off)s; border-color: %(btn_off_line)s;
                               color: %(btn_off_text)s; }

QProgressBar {
    background: %(track)s; border: 1px solid %(line)s; border-radius: 7px;
    min-height: 12px; max-height: 12px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 %(bar_top)s, stop:1 %(bar_bottom)s);
    border-radius: 6px;
}

QScrollBar:vertical { background: transparent; width: 12px; margin: 2px; }
QScrollBar::handle:vertical { background: %(handle)s; border-radius: 5px;
                              min-height: 34px; }
QScrollBar::handle:vertical:hover   { background: %(handle_hover)s; }
QScrollBar::handle:vertical:pressed { background: %(handle_press)s; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }
QScrollBar:horizontal, QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal { height: 0; background: transparent; }

QStatusBar {
    background: %(page)s; color: %(mute)s; font-size: 13px;
    border-top: 1px solid %(line)s;
}
QStatusBar::item { border: none; }
QToolTip {
    background: %(ink)s; color: %(on_dark)s; border: 1px solid %(deep)s;
    border-radius: 8px; padding: 6px 9px; font-size: 13px;
}
"""


def qss():
    """The sheet every widget reads."""
    return _TEMPLATE % P
