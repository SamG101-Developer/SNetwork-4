from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from src.setup.CmdHandler import CmdHandler


class MainWindow(QWidget):
    _cmd_handler: CmdHandler

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._cmd_handler = CmdHandler()

        # Create the grid layout.
        layout = QGridLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        # Add a banner to the top of the layout
        layout.addWidget(BannerWidget(), 0, 0, 1, 4)

        # Add the buttons
        self._join_button = AppItem(
            parent=self, text="Join Network", icon="./icons/join_network.svg", clicked=self.join)
        self._route_button = AppItem(
            parent=self, text="Create Route", icon="./icons/create_route.svg", clicked=self.route, disabled=True)
        self._store_button = AppItem(
            parent=self, text="Store Data", icon="./icons/store_data.svg", clicked=self.store, disabled=True)
        self._retrieve_button = AppItem(
            parent=self, text="Retrieve Data", icon="./icons/retrieve_data.svg", clicked=self.retrieve, disabled=True)
        self._keygen_button = AppItem(
            parent=self, text="Keygen", icon="./icons/keygen.svg", clicked=self.keygen, disabled=True)
        self._directory_button = AppItem(
            parent=self, text="Directory Node", icon="./icons/directory_node.svg", clicked=self.directory, large=True)
        self._reset_button = AppItem(
            parent=self, text="Reset Node", icon="./icons/reset_node.svg", clicked=self.reset, disabled=True)

        # Add the buttons to the layout
        layout.addWidget(self._join_button, 1, 0)
        layout.addWidget(self._route_button, 1, 1)
        layout.addWidget(self._store_button, 1, 2)
        layout.addWidget(self._retrieve_button, 1, 3)
        layout.addWidget(self._keygen_button, 2, 0)
        layout.addWidget(self._directory_button, 2, 1, 1, 2)
        layout.addWidget(self._reset_button, 2, 3)

        # Set the layout of the main window
        self.setLayout(layout)
        self.setStyleSheet("MainWindow {background-color: #404040;}")
        self.showMaximized()

    def join(self) -> None:
        # Button states
        self._join_button._activated = True
        self._join_button.setDisabled(True)
        self._route_button.setDisabled(False)

        # Map command
        self._cmd_handler._handle("join", None)

    def route(self) -> None:
        # Button states
        self._route_button._activated = True
        self._route_button.setDisabled(True)
        self._store_button.setDisabled(False)
        self._retrieve_button.setDisabled(False)

        # Map command
        self._cmd_handler._handle("route", None)

    def store(self) -> None:
        # Map to "python src/main.py store" (disable after clicking)
        open_file_dialog = QFileDialog()
        file_name, _ = open_file_dialog.getOpenFileName(self, "Open File", "", "All Files (*)")

    def retrieve(self) -> None:
        # Map to "python src/main.py retrieve" (disable after clicking)
        ...

    def keygen(self) -> None:
        ...

    def directory(self) -> None:
        # Button states
        self._directory_button._activated = True
        self._directory_button.setDisabled(True)
        self._join_button.setDisabled(True)

        # Map command
        self._cmd_handler._handle("directory", None)

    def reset(self) -> None:
        ...


class BannerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

    def paintEvent(self, event: QPaintEvent):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(32, 32, 32))
        painter.drawRoundedRect(0, 0, self.width(), self.height(), 16, 16)

        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        painter.setFont(font)

        painter.setPen(QPen(QColor("#404040")))
        painter.drawText(0, 0, self.width(), self.height(), Qt.AlignmentFlag.AlignCenter, "SNetwork Anonymous Network")


class AppItem(QPushButton):
    _activated: bool

    def __init__(self, parent=None, **kwargs):
        super().__init__(parent)
        self._activated = False
        self._text = kwargs.get("text", "")
        self._icon = kwargs.get("icon", "")
        self.clicked.connect(kwargs.get("clicked", lambda: None))
        self.setDisabled(kwargs.get("disabled", False))

        policy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        policy.setHeightForWidth(False) if kwargs.get("large", False) else policy.setHeightForWidth(True)
        self.setSizePolicy(policy)

        self._hover_animation = QVariantAnimation(self)
        self._hover_animation.setStartValue(QColor(32, 32, 32))
        self._hover_animation.setEndValue(QColor(48, 48, 48))
        self._hover_animation.valueChanged.connect(self.repaint)
        self._hover_animation.setDuration(150)
        self._hover_animation.setEasingCurve(QEasingCurve.Type.InOutSine)

        self._disabled_color = QColor(48, 48, 48)

    def sizeHint(self):
        return QSize(self.width(), self.width())

    def heightForWidth(self, width: int):
        return width

    def paintEvent(self, event: QPaintEvent):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen if self.isEnabled() and not self._activated else QPen(QColor(0, 255, 0)) if self._activated else QPen(QColor(255, 0, 0), 2))
        painter.setBrush(self._hover_animation.currentValue() if self.isEnabled() else self._disabled_color)

        painter.drawRoundedRect(0, 0, self.width(), self.height(), 16, 16)
        pixmap = QPixmap(self._icon)
        pixmap = pixmap.scaled(self.width() // 2, self.height() // 2, Qt.AspectRatioMode.KeepAspectRatio,
                               Qt.TransformationMode.SmoothTransformation)
        painter.drawPixmap((self.width() - pixmap.width()) // 2, self.height() // 8, pixmap)

        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        painter.setFont(font)

        painter.setPen(QPen(QColor("#404040")))
        painter.drawText(0, self.height() // 2, self.width(), 3 * self.height() // 4, Qt.AlignmentFlag.AlignCenter,
                         self._text)

    def event(self, event: QEvent):
        if event.type() == QEvent.Type.HoverEnter and self.isEnabled():
            self._hover_animation.stop()
            self._hover_animation.setDirection(QVariantAnimation.Direction.Forward)
            self._hover_animation.start()
        elif event.type() == QEvent.Type.HoverLeave and self.isEnabled():
            self._hover_animation.stop()
            self._hover_animation.setDirection(QVariantAnimation.Direction.Backward)
            self._hover_animation.start()
        return super().event(event)
