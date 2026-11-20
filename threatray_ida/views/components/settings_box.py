from threatray_ida.application.validation_error import ValidationError
from threatray_ida.qt_compat import QDialog, QDialogButtonBox, Qt, QtWidgets, get_dialog_parent
from threatray_ida.views.controllers.settings_controller import SettingsController


class SettingsBox(QDialog):

    def __init__(self, controller: SettingsController, parent=None):
        super().__init__(parent or get_dialog_parent())
        self.__controller = controller
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle(self.__controller.header)
        self.vertical_layout = QtWidgets.QVBoxLayout(self)

        # header label
        info_label = QtWidgets.QLabel(self.__controller.info_label)
        self.vertical_layout.addWidget(info_label)

        # Instance name and API key input
        self.form_layout = QtWidgets.QFormLayout()

        self.realm_input = QtWidgets.QLineEdit(self.__controller.realm)
        self.form_layout.addRow('Instance name', self.realm_input)

        self.api_key_input = QtWidgets.QLineEdit(self.__controller.api_key)
        self.api_key_input.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.form_layout.addRow('API key', self.api_key_input)

        self.vertical_layout.addLayout(self.form_layout)

        self.error_label = QtWidgets.QLabel()
        self.error_label.setVisible(False)
        self.vertical_layout.addWidget(self.error_label)

        # footer label
        footer_label = QtWidgets.QLabel(self.__controller.footer)
        self.vertical_layout.addWidget(footer_label)

        self.button_box = QtWidgets.QDialogButtonBox()
        self.button_box.setOrientation(Qt.Orientation.Horizontal)
        self.button_box.setStandardButtons(QDialogButtonBox.StandardButton.Cancel
                                           | QDialogButtonBox.StandardButton.Ok)

        self.vertical_layout.addWidget(self.button_box)

        self.button_box.accepted.connect(self.__accepted)
        self.button_box.rejected.connect(self.reject)

    def __accepted(self):
        try:
            self.__controller.save_settings(realm=self.realm_input.text(), api_key=self.api_key_input.text())
        except (ValidationError, OSError) as e:
            self.error_label.setText(str(e))
            self.error_label.setVisible(True)
            return
        self.accept()
