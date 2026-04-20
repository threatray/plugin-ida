from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt  # pylint: disable=no-name-in-module
from PyQt5.QtWidgets import QDialog, QDialogButtonBox  # pylint: disable=no-name-in-module

from threatray_ida.views.controllers.settings_controller import SettingsController


class SettingsBox(QDialog):

    def __init__(self, controller: SettingsController, parent=None):
        super().__init__(parent)
        self.__controller = controller
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle(self.__controller.header)
        self.vertical_layout = QtWidgets.QVBoxLayout(self)

        # header label
        info_label = QtWidgets.QLabel(self.__controller.info_label)
        self.vertical_layout.addWidget(info_label)

        # Realm and api key input
        self.form_layout = QtWidgets.QFormLayout()

        realm_label = QtWidgets.QLabel('Realm')
        self.form_layout.setWidget(0, QtWidgets.QFormLayout.LabelRole, realm_label)
        self.realm_input = QtWidgets.QLineEdit(self.__controller.realm)
        self.realm_input.setMaximumWidth(250)  # Limit width
        self.form_layout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.realm_input)

        api_key_label = QtWidgets.QLabel('API key')
        self.form_layout.setWidget(1, QtWidgets.QFormLayout.LabelRole, api_key_label)
        self.api_key_input = QtWidgets.QLineEdit(self.__controller.api_key)
        self.form_layout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.api_key_input)

        self.vertical_layout.addLayout(self.form_layout)

        # footer label
        footer_label = QtWidgets.QLabel(self.__controller.footer)
        self.vertical_layout.addWidget(footer_label)

        self.button_box = QtWidgets.QDialogButtonBox()
        self.button_box.setOrientation(Qt.Horizontal)
        self.button_box.setStandardButtons(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)

        self.vertical_layout.addWidget(self.button_box)

        self.button_box.accepted.connect(self.__accepted)
        self.button_box.rejected.connect(self.__rejected)

    def __accepted(self):
        realm = self.realm_input.text()
        api_key = self.api_key_input.text()
        self.__controller.save_settings(realm=realm, api_key=api_key)
        self.close()

    def __rejected(self):
        self.close()
