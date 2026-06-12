import sys
import os
import string
import secrets
import time
import logging
import json
import uuid
from typing import List, Tuple, Optional, Dict, Any

# --- DEPENDENCIAS OPCIONALES/NUEVAS ---
try:
    import argon2
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

try:
    import qrcode
    import io
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    import g19_rc
except ImportError:
    pass  # Ignorar si no está compilado el archivo de recursos aún

from platformdirs import user_config_dir
from cryptography.fernet import Fernet

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QLineEdit, QProgressBar, 
    QMessageBox, QInputDialog, QFileDialog
)
from PySide6.QtCore import (
    QLocale, QTranslator, Slot, QIODevice, QFile, QSettings, 
    QCoreApplication, QObject, Signal, QRunnable, QThreadPool, QEvent
)
from PySide6.QtGui import QClipboard, QPixmap, QImage
from PySide6.QtUiTools import QUiLoader

from license_manager import LicenseManager
from cipherpass_core.generators import PasswordEngine, TOTPEngine, DEFAULT_SYMBOLS
from cipherpass_core.analyzers import StrengthAnalyzer
from cipherpass_core.crypto_vault import VaultExporter
from cipherpass_core.hibp import HIBPClient

# --- CONFIGURACIÓN DE LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# --- CONSTANTES ---
LANG_MAP: dict = {"Español": "es", "English": "en", "Português": "pt"}
VERSION = "1.0.3"

# --- GESTIÓN DE RUTAS ---
def resource_path(relative_path: str) -> str:
    """Obtiene la ruta absoluta al recurso, funciona para dev y para PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# --- GESTIÓN DE CONFIGURACIÓN ---
class SettingsManager:
    """Gestiona la persistencia de configuraciones de la aplicación."""
    def __init__(self) -> None:
        self.settings = QSettings("CipherPass", "CipherPassApp")

    def get_language(self) -> str:
        return str(self.settings.value("language", "es")).strip()

    def set_language(self, lang_code: str) -> None:
        self.settings.setValue("language", lang_code.strip())

# --- COMPLIANCE MANAGER ---
class ComplianceManager:
    """Administra los preajustes normativos de seguridad."""
    _PRESETS = None

    @classmethod
    def _load_presets(cls) -> None:
        if cls._PRESETS is not None:
            return
            
        rules_path = resource_path(os.path.join("resources", "compliance_rules.json"))
        
        # Esquema esperado para cada normativa
        expected_schema = {
            "length": int, "upper": bool, "lower": bool, 
            "nums": bool, "syms": bool, "min_n": int, "min_s": int
        }
        
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                raw_presets = json.load(f)
                
            if not isinstance(raw_presets, dict):
                raise ValueError("El archivo JSON debe contener un objeto/diccionario en su raíz.")

            valid_presets = {}
            for preset_name, rules in raw_presets.items():
                if not isinstance(rules, dict):
                    continue
                # Verificar que existan todas las llaves y coincidan en tipo
                if all(k in rules and isinstance(rules[k], t) for k, t in expected_schema.items()):
                    valid_presets[preset_name] = rules
                else:
                    logging.warning(f"Ignorando preset '{preset_name}' por formato inválido o llaves faltantes.")
                    
            if not valid_presets:
                raise ValueError("No se encontraron presets válidos en el archivo.")
                
            cls._PRESETS = valid_presets
            
        except Exception as e:
            logging.error(f"Error cargando o validando {rules_path}: {e}. Usando valores predeterminados.")
            # Fallback seguro
            cls._PRESETS = {
                "Active Directory": {"length": 14, "upper": True, "lower": True, "nums": True, "syms": True, "min_n": 1, "min_s": 1},
                "AWS IAM": {"length": 16, "upper": True, "lower": True, "nums": True, "syms": True, "min_n": 1, "min_s": 1},
                "PCI-DSS": {"length": 12, "upper": True, "lower": True, "nums": True, "syms": True, "min_n": 1, "min_s": 1},
                "NIST 800-63B": {"length": 15, "upper": True, "lower": True, "nums": False, "syms": False, "min_n": 0, "min_s": 0}
            }

    @classmethod
    def get_preset_rules(cls, preset_name: str) -> Optional[Dict[str, Any]]:
        cls._load_presets()
        return cls._PRESETS.get(preset_name)

# --- GESTOR CRIPTOGRÁFICO ---
class CryptoManager:
    """Gestiona la clave de cifrado maestra local para los diccionarios Diceware.
    
    Esta clase se encarga de crear o recuperar una clave simétrica de Fernet 
    almacenada en el directorio de configuración del usuario.
    """
    @staticmethod
    def get_cipher_suite() -> Fernet:
        """Obtiene la suite criptográfica para cifrado y descifrado local.
        
        Returns:
            Fernet: Instancia de Fernet inicializada con la clave local.
        """
        config_dir = user_config_dir("CipherPass", "CipherPassApp")
        os.makedirs(config_dir, exist_ok=True)
        key_file = os.path.join(config_dir, "secret.key")
        
        try:
            if os.path.exists(key_file):
                with open(key_file, "rb") as f:
                    return Fernet(f.read().strip())
            else:
                new_key = Fernet.generate_key()
                with open(key_file, "wb") as f:
                    f.write(new_key)
                return Fernet(new_key)
            
        except Exception as e:
            logging.error(f"Error crítico al gestionar la clave: {e}")
            return Fernet(Fernet.generate_key())

# --- WORKER ASÍNCRONO PARA HIBP ---
class HIBPSignals(QObject):
    finished = Signal(int, str)

class HIBPWorker(QRunnable):
    """Consulta la API de Pwned Passwords mediante K-Anonymity sin bloquear la UI."""
    def __init__(self, password: str):
        super().__init__()
        self.password = password
        self.signals = HIBPSignals()

    @Slot()
    def run(self):
        count, error_msg = HIBPClient.check_password(self.password)
        self.signals.finished.emit(count, error_msg)
        del self.password

# --- UI HELPER QR ---
class QRHelper:
    @staticmethod
    def generate_pixmap(uri: str, size: int = 200) -> Optional[QPixmap]:
        if not HAS_QRCODE: return None
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            byte_io = io.BytesIO()
            img.save(byte_io, 'PNG')
            byte_io.seek(0)
            
            qimg = QImage()
            qimg.loadFromData(byte_io.read())
            return QPixmap.fromImage(qimg).scaled(size, size)
        except Exception as e:
            logging.error(f"Fallo al generar QR: {e}")
            return None


# --- INTERFAZ PRINCIPAL ---
class CipherPassApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.settings = SettingsManager()
        self.engine = PasswordEngine(cipher_suite=CryptoManager.get_cipher_suite())
        self.license_manager = LicenseManager(self.settings)
        self.vault_exporter = VaultExporter()
        self.threadpool = QThreadPool()
        
        self.current_locale = QLocale(self.settings.get_language())
        self.translator = QTranslator()
        self.ui = None
        
        self.init_ui()

    def init_ui(self) -> None:
        self.load_translation(self.current_locale.name().split("_")[0])
        self.load_ui_file()
        if self.ui:
            self.setWindowTitle("CipherPass")
            self.show()

    def load_translation(self, lang_code: str) -> None:
        QApplication.instance().removeTranslator(self.translator)
        translation_path = resource_path(os.path.join("resources", "lang"))
        if self.translator.load(f"lang_{lang_code}.qm", translation_path):
            QApplication.instance().installTranslator(self.translator)
            logging.info(f"Traducción cargada: {lang_code}")
        else:
            logging.warning(f"No se pudo cargar la traducción para: {lang_code}")

    def load_ui_file(self) -> None:
        lang_code = self.current_locale.name().split("_")[0]
        ui_file_path = resource_path(os.path.join("ui", f"main_{lang_code}.ui"))
        
        if not os.path.exists(ui_file_path):
            logging.warning(f"UI {ui_file_path} no encontrada. Fallback a (es).")
            ui_file_path = resource_path(os.path.join("ui", "main_es.ui"))
            lang_code = "es"

        loader = QUiLoader()
        file = QFile(ui_file_path)
        if not file.open(QIODevice.ReadOnly):
            logging.error(f"Imposible abrir archivo UI: {ui_file_path}")
            return

        self.ui = loader.load(file)
        file.close()

        if not self.ui:
            logging.error(f"Fallo al construir UI: {loader.errorString()}")
            return

        self.setCentralWidget(self.ui)
        icon = self.ui.windowIcon()
        if not icon.isNull():
            self.setWindowIcon(icon)
            
        filepath = resource_path(os.path.join("resources", "diceware", f"diceware_{lang_code}.enc"))
        self.engine.load_diceware(filepath)
        self.connect_ui_elements()

    def connect_ui_elements(self) -> None:
        # 1. Idioma
        self.ui.comboBox_idioma.blockSignals(True)
        self.ui.comboBox_idioma.clear()
        for lang_name, code in LANG_MAP.items():
            self.ui.comboBox_idioma.addItem(lang_name, code)
        current_code = self.current_locale.name().split("_")[0]
        idx = self.ui.comboBox_idioma.findData(current_code)
        if idx != -1: self.ui.comboBox_idioma.setCurrentIndex(idx)
        self.ui.comboBox_idioma.blockSignals(False)
        self.ui.comboBox_idioma.currentIndexChanged.connect(self.change_language)

        # Limpieza de memoria al cambiar de pestaña
        self.ui.tabWidget.currentChanged.connect(self.on_tab_changed)

        # 2. Generador Contraseña Original
        spinboxes = [self.ui.spinBox_longitud, self.ui.spinBox_min_numeros, self.ui.spinBox_min_especiales]
        for w in spinboxes:
            w.valueChanged.connect(self.validate_spinbox_contrasena)
            w.valueChanged.connect(self.update_password_strength)
        checkboxes = [
            self.ui.checkBox_mayusculas, self.ui.checkBox_minusculas,
            self.ui.checkBox_numeros, self.ui.checkBox_simbolos, self.ui.checkBox_evitar_ambiguos
        ]
        for chk in checkboxes:
            chk.stateChanged.connect(self.update_password_strength)
            
        self.ui.btn_generar_contrasena.clicked.connect(self.generate_password_ui)
        self.ui.btn_copiar_contrasena.clicked.connect(lambda: self.copy_to_clipboard(self.ui.lineEdit_contrasena))
        self.update_password_strength()

        # 3. Frase & Usuario Original
        self.ui.btn_generar_frase.clicked.connect(self.generate_passphrase_ui)
        self.ui.btn_copiar_frase.clicked.connect(lambda: self.copy_to_clipboard(self.ui.lineEdit_frase))
        
        self.ui.comboBox_tipo_usuario.setCurrentIndex(1)
        self.ui.checkBox_usuario_servicio.stateChanged.connect(self.toggle_service_tag_field)
        self.toggle_service_tag_field(self.ui.checkBox_usuario_servicio.isChecked())
        self.ui.btn_generar_usuario.clicked.connect(self.generate_username_ui)
        self.ui.btn_copiar_usuario.clicked.connect(lambda: self.copy_to_clipboard(self.ui.lineEdit_usuario))

        # 4. Validar Pasivo Original
        self.ui.btn_validar_ver.toggled.connect(self.toggle_password_visibility)
        self.ui.lineEdit_validar_pass.textChanged.connect(self.analyze_password_strength)

        # 5. Integraciones PRO (Tokens, Compliance, HIBP, Vault, TOTP)
        self.ui.btn_generar_token.clicked.connect(self.generate_token_ui)
        self.ui.btn_copiar_token.clicked.connect(lambda: self.copy_to_clipboard(self.ui.lineEdit_token_resultado))
        
        # Cargar dinámicamente presets de Compliance respetando el elemento 0 ('Modo manual' traducido por PySide6)
        self.ui.comboBox_compliance.blockSignals(True)
        while self.ui.comboBox_compliance.count() > 1:
            self.ui.comboBox_compliance.removeItem(1)
        ComplianceManager._load_presets()
        if ComplianceManager._PRESETS:
            self.ui.comboBox_compliance.addItems(list(ComplianceManager._PRESETS.keys()))
        self.ui.comboBox_compliance.blockSignals(False)
        
        self.ui.comboBox_compliance.currentIndexChanged.connect(self.apply_compliance_preset)
        self.ui.btn_manual_mode.clicked.connect(self.enable_manual_mode)
        self.ui.btn_hibp_check.clicked.connect(self.check_hibp)
        self.ui.btn_export_vault.clicked.connect(self.export_vault_ui)
        self.ui.btn_import_vault.clicked.connect(self.import_vault_ui)
        self.ui.btn_browse_vault.clicked.connect(self.browse_vault_file)
        self.ui.btn_generar_totp.clicked.connect(self.generate_totp_ui)
        self.ui.btn_copiar_totp.clicked.connect(lambda: self.copy_to_clipboard(self.ui.lineEdit_totp_secret))
        self.ui.btn_copiar_uri.clicked.connect(lambda: self.copy_to_clipboard(self.ui.lineEdit_totp_uri))
        self.ui.btn_save_qr.clicked.connect(self.save_qr_ui)

        # 6. Licencia
        self.ui.btn_activate_license.clicked.connect(self.handle_license_activation)
        self.ui.btn_deactivate_license.clicked.connect(self.handle_license_deactivation)

        # Configurar menú superior
        self._setup_menus()

        # Interceptar clics en pestañas y áreas deshabilitadas para mostrar CTA de PRO
        self.ui.tabWidget.tabBar().installEventFilter(self)
        self.ui.tab_contrasena.installEventFilter(self)
        self.ui.tab_validar.installEventFilter(self)

        self._apply_pro_gates()

    def _apply_pro_gates(self) -> None:
        """Bloquea o desbloquea funcionalidades según el estado de la licencia."""
        is_pro = self.license_manager.is_pro_active()
        try:
            self.ui.tab_tokens.setEnabled(is_pro)
            self.ui.tab_vault.setEnabled(is_pro)
            self.ui.tab_totp.setEnabled(is_pro)
            
            self.ui.frame_compliance.setEnabled(is_pro)
            self.ui.comboBox_compliance.setEnabled(is_pro)
            self.ui.btn_manual_mode.setEnabled(is_pro)
            
            self.ui.frame_hibp.setEnabled(is_pro)
            self.ui.checkBox_hibp.setEnabled(is_pro)
            self.ui.btn_hibp_check.setEnabled(is_pro)

            self.ui.label_license_status.setText("Estado: ACTIVADO (PRO)" if is_pro else "Estado: No activado (Free)")
            self.ui.label_license_status.setStyleSheet(
                "font-weight: bold; padding: 8px; border-radius: 4px; background-color: #198754;" if is_pro else 
                "font-weight: bold; padding: 8px; border-radius: 4px; background-color: #353535;"
            )
            self.ui.btn_deactivate_license.setEnabled(is_pro)
            self.ui.lineEdit_license_key.setEnabled(not is_pro)
            self.ui.btn_activate_license.setEnabled(not is_pro)
            self.ui.label_licencia.setText("🔓 Versión PRO" if is_pro else "🔒 Versión Free")
        except AttributeError as e:
            logging.warning(f"No se pudo aplicar regla PRO a widget inexistente: {e}")

    def _setup_menus(self) -> None:
        """Configura la barra de menús superior."""
        menu_bar = self.menuBar()
        menu_bar.clear()  # Evitar duplicados al cambiar de idioma
        
        lang_code = self.current_locale.name().split("_")[0]
        ayuda_text = {
            "en": "Help",
            "pt": "Ajuda"
        }.get(lang_code, "Ayuda")
        
        acerca_text = {
            "en": "About CipherPass...",
            "pt": "Sobre CipherPass..."
        }.get(lang_code, "Acerca de CipherPass...")
        
        help_menu = menu_bar.addMenu(ayuda_text)
        about_action = help_menu.addAction(acerca_text)
        about_action.triggered.connect(self.show_about_dialog)

    @Slot()
    def show_about_dialog(self) -> None:
        """Muestra el diálogo de información de la aplicación."""
        is_pro = self.license_manager.is_pro_active()
        lang_code = self.current_locale.name().split("_")[0]
        
        estado = {
            "en": "⭐ PRO (Activated)" if is_pro else "🔒 Free (Not activated)",
            "pt": "⭐ PRO (Ativada)" if is_pro else "🔒 Free (Não ativada)"
        }.get(lang_code, "⭐ PRO (Activada)" if is_pro else "🔒 Free (No activada)")
        
        version_lbl = {"en": "Version:", "pt": "Versão:"}.get(lang_code, "Versión:")
        license_lbl = {"en": "Current license:", "pt": "Licença atual:"}.get(lang_code, "Licencia actual:")
        desc_lbl = {
            "en": "Desktop application designed to generate, validate, and protect cryptographic credentials ensuring your privacy offline-first.",
            "pt": "Aplicativo de desktop projetado para gerar, validar e proteger credenciais criptográficas garantindo sua privacidade offline-first."
        }.get(lang_code, "Aplicación de escritorio diseñada para generar, validar y proteger credenciales criptográficas asegurando tu privacidad offline-first.")
        visit_lbl = {"en": "Visit the official website", "pt": "Visitar o site oficial"}.get(lang_code, "Visitar el sitio web oficial")
        about_title = {"en": "About CipherPass", "pt": "Sobre o CipherPass"}.get(lang_code, "Acerca de CipherPass")
        
        # QMessageBox.about interpreta HTML nativamente
        texto_html = (
            f"<h2>CipherPass</h2>"
            f"<p><b>{version_lbl}</b> {VERSION}</p>"
            f"<p><b>{license_lbl}</b> {estado}</p>"
            f"<hr>"
            f"<p>{desc_lbl}</p>"
            f"<p><a href='https://github.com/tu-usuario/CipherPass_Pro'>{visit_lbl}</a></p>"
        )
        QMessageBox.about(self, about_title, texto_html)

    # --- FILTRO DE EVENTOS (INTERCEPTAR CLICS EN ÁREAS PRO) ---
    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.MouseButtonPress and not self.license_manager.is_pro_active():
            # Interceptar clics en las Pestañas (TabBar)
            if obj == self.ui.tabWidget.tabBar():
                index = obj.tabAt(event.position().toPoint())
                if index != -1:
                    target_widget = self.ui.tabWidget.widget(index)
                    pro_tabs = [self.ui.tab_tokens, self.ui.tab_vault, self.ui.tab_totp]
                    if target_widget in pro_tabs:
                        self.show_pro_cta()
                        return True  # Consume el evento
            
            # Interceptar clics en el recuadro de Compliance
            elif obj == self.ui.tab_contrasena:
                if self.ui.frame_compliance.geometry().contains(event.position().toPoint()):
                    self.show_pro_cta()
                    return True

            # Interceptar clics en el recuadro de HIBP
            elif obj == self.ui.tab_validar:
                if self.ui.frame_hibp.geometry().contains(event.position().toPoint()):
                    self.show_pro_cta()
                    return True

        return super().eventFilter(obj, event)

    def show_pro_cta(self) -> None:
        """Muestra el diálogo de llamada a la acción para la versión PRO."""
        msg = QMessageBox(self)
        msg.setWindowTitle(QCoreApplication.translate("CipherPassApp", "🔒 Función PRO Requerida"))
        msg.setText(QCoreApplication.translate("CipherPassApp", "Esta característica es exclusiva de la versión CipherPass PRO."))
        msg.setInformativeText(QCoreApplication.translate("CipherPassApp", "¿Deseas ir a la pestaña de activación para introducir tu licencia o adquirir una?"))
        msg.setIcon(QMessageBox.Information)
        btn_yes = msg.addButton(QCoreApplication.translate("CipherPassApp", "Ir a PRO"), QMessageBox.ActionRole)
        msg.addButton(QCoreApplication.translate("CipherPassApp", "Cancelar"), QMessageBox.RejectRole)
        
        msg.exec()
        if msg.clickedButton() == btn_yes:
            pro_index = self.ui.tabWidget.indexOf(self.ui.tab_pro)
            if pro_index != -1:
                self.ui.tabWidget.setCurrentIndex(pro_index)

    # --- SLOTS PRO Y LICENCIA ---
    @Slot()
    def handle_license_activation(self) -> None:
        key = self.ui.lineEdit_license_key.text()
        if self.license_manager.activate_license(key):
            QMessageBox.information(self, "¡Éxito!", "Licencia CipherPass PRO activada correctamente.")
            self._apply_pro_gates()
        else:
            QMessageBox.warning(self, "Error", "Clave de licencia inválida.")

    @Slot()
    def handle_license_deactivation(self) -> None:
        self.license_manager.deactivate_license()
        self._apply_pro_gates()
        QMessageBox.information(self, "Desactivado", "Tu licencia ha sido removida del dispositivo.")

    # --- SLOTS ORIGINALES DE UI ---
    @Slot()
    def update_password_strength(self) -> None:
        current_pwd = self.ui.lineEdit_contrasena.text()
        if current_pwd and current_pwd != "Selecciona opciones":
            val, color, msg_key, _, _ = StrengthAnalyzer.get_unified_metrics(current_pwd)
            msg = QCoreApplication.translate("CipherPassApp", msg_key)
        else:
            val, color, msg_key = StrengthAnalyzer.calculate_entropy_preview(
                self.ui.spinBox_longitud.value(), self.ui.checkBox_mayusculas.isChecked(),
                self.ui.checkBox_minusculas.isChecked(), self.ui.checkBox_numeros.isChecked(),
                self.ui.checkBox_simbolos.isChecked()
            )
            msg = QCoreApplication.translate("CipherPassApp", msg_key)
        self.ui.progressBar_fortaleza.setValue(val)
        self.ui.progressBar_fortaleza.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")
        self.ui.progressBar_fortaleza.setFormat(f"{msg} ({val}%)")

    @Slot()
    def analyze_password_strength(self) -> None:
        pwd = self.ui.lineEdit_validar_pass.text()
        if not pwd:
            self.reset_validar_ui()
            return
        val, color, msg_key, crack_seconds, warning_key = StrengthAnalyzer.get_unified_metrics(pwd)
        
        msg = QCoreApplication.translate("CipherPassApp", msg_key)
        warning = QCoreApplication.translate("CipherPassApp", warning_key) if warning_key else ""
        time_text = self._format_crack_time(crack_seconds)
        
        if warning: msg += f" ({warning})"
        self.ui.label_validar_tiempo.setText(f"Tiempo estimado: {time_text}")
        self.ui.progressBar_validar.setValue(val)
        self.ui.progressBar_validar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")
        self.ui.label_validar_mensaje.setText(msg)

    def _format_crack_time(self, seconds: float) -> str:
        if seconds < 1:
            return QCoreApplication.translate("CipherPassApp", "Instantáneo")
        if seconds < 60:
            return QCoreApplication.translate("CipherPassApp", f"{int(seconds)} s")
        if seconds < 3600:
            return QCoreApplication.translate("CipherPassApp", f"{int(seconds/60)} min")
        if seconds < 86400:
            return QCoreApplication.translate("CipherPassApp", f"{int(seconds/3600)} h")
        if seconds < 31536000:
            return QCoreApplication.translate("CipherPassApp", f"{int(seconds/86400)} días")
        if seconds < 315360000:
            return QCoreApplication.translate("CipherPassApp", f"{int(seconds/31536000)} años")
        return QCoreApplication.translate("CipherPassApp", "Siglos")

    @Slot(bool)
    def toggle_service_tag_field(self, checked: bool) -> None:
        self.ui.lineEdit_usuario_servicio.setEnabled(checked)

    @Slot(bool)
    def toggle_password_visibility(self, checked: bool) -> None:
        self.ui.lineEdit_validar_pass.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    @Slot(int)
    def change_language(self, index: int) -> None:
        lang_code = self.ui.comboBox_idioma.itemData(index)
        current = self.current_locale.name().split("_")[0]
        if lang_code and lang_code != current:
            self.current_locale = QLocale(lang_code)
            self.settings.set_language(lang_code)
            self.load_translation(lang_code)
            self.load_ui_file()

    @Slot(int)
    def on_tab_changed(self, index: int) -> None:
        """Sobrescribe y limpia los datos sensibles cuando se sale de la pestaña de la bóveda."""
        current_widget = self.ui.tabWidget.widget(index)
        if current_widget != self.ui.tab_vault:
            # Sobrescribir con ceros antes de vaciar fuerza el borrado en el buffer C++ (QTextDocument)
            import_len = len(self.ui.textEdit_import_data.toPlainText())
            if import_len > 0:
                self.ui.textEdit_import_data.setPlainText("0" * import_len)
                self.ui.textEdit_import_data.clear()
                
            export_len = len(self.ui.textEdit_export_data.toPlainText())
            if export_len > 0:
                self.ui.textEdit_export_data.setPlainText("0" * export_len)
                self.ui.textEdit_export_data.clear()
                
            self.ui.label_vault_estado.clear()

    def validate_spinbox_contrasena(self) -> None:
        length = self.ui.spinBox_longitud.value()
        req = self.ui.spinBox_min_numeros.value() + self.ui.spinBox_min_especiales.value()
        if req > length:
            self.ui.spinBox_longitud.setValue(req)

    # --- SLOTS GENERACIÓN ---
    def generate_password_ui(self) -> None:
        self.ui.btn_generar_contrasena.setEnabled(False)
        QApplication.processEvents()
        pwd = self.engine.generate_password(
            self.ui.spinBox_longitud.value(), self.ui.spinBox_min_numeros.value(),
            self.ui.spinBox_min_especiales.value(), self.ui.checkBox_mayusculas.isChecked(),
            self.ui.checkBox_minusculas.isChecked(), self.ui.checkBox_numeros.isChecked(),
            self.ui.checkBox_simbolos.isChecked(), self.ui.checkBox_evitar_ambiguos.isChecked()
        )
        self.ui.lineEdit_contrasena.setText(pwd if pwd else "Selecciona opciones")
        self.update_password_strength()
        self.ui.btn_generar_contrasena.setEnabled(True)

    def generate_passphrase_ui(self) -> None:
        phrase = self.engine.generate_passphrase(
            self.ui.spinBox_num_palabras.value(), self.ui.checkBox_capitalizar.isChecked(),
            self.ui.checkBox_incluir_numeros.isChecked(), self.ui.lineEdit_separador.text()
        )
        self.ui.lineEdit_frase.setText(phrase if phrase else "Error: Sin diccionario")

    def generate_username_ui(self) -> None:
        username = self.engine.generate_username(
            self.ui.comboBox_tipo_usuario.currentIndex(), self.ui.lineEdit_usuario_dominio.text(),
            self.ui.lineEdit_usuario_servicio.text(), self.ui.checkBox_usuario_servicio.isChecked()
        )
        self.ui.lineEdit_usuario.setText(username)

    def reset_validar_ui(self) -> None:
        self.ui.label_validar_tiempo.setText("Tiempo estimado: -")
        self.ui.progressBar_validar.setValue(0)
        self.ui.progressBar_validar.setStyleSheet("")
        self.ui.label_validar_mensaje.setText(QCoreApplication.translate("CipherPassApp", "Ingresa una contraseña..."))

    def copy_to_clipboard(self, widget: QLineEdit) -> None:
        QApplication.clipboard().setText(widget.text())

    # --- NUEVOS SLOTS PRO: Tokens, Compliance, HIBP, Vault, TOTP ---
    @Slot()
    def generate_token_ui(self) -> None:
        mode = self.ui.comboBox_token_tipo.currentIndex()
        length = self.ui.spinBox_token_length.value()
        token = self.engine.generate_api_token(mode, length)
        self.ui.lineEdit_token_resultado.setText(token)

    @Slot(int)
    def apply_compliance_preset(self, index: int) -> None:
        controls = [
            self.ui.spinBox_longitud, self.ui.checkBox_mayusculas,
            self.ui.checkBox_minusculas, self.ui.checkBox_numeros,
            self.ui.checkBox_simbolos, self.ui.spinBox_min_numeros,
            self.ui.spinBox_min_especiales, self.ui.checkBox_evitar_ambiguos
        ]
        
        if index == 0: 
            for ctrl in controls:
                ctrl.setEnabled(True)
                
            # Restaurar los valores por defecto del inicio de la aplicación
            self.ui.spinBox_longitud.blockSignals(True)
            self.ui.spinBox_longitud.setValue(14)
            self.ui.checkBox_mayusculas.setChecked(True)
            self.ui.checkBox_minusculas.setChecked(True)
            self.ui.checkBox_numeros.setChecked(True)
            self.ui.checkBox_simbolos.setChecked(True)
            self.ui.checkBox_evitar_ambiguos.setChecked(False)
            self.ui.spinBox_min_numeros.setValue(1)
            self.ui.spinBox_min_especiales.setValue(1)
            self.ui.spinBox_longitud.blockSignals(False)
            
            self.ui.label_compliance_badge.setVisible(False)
            self.update_password_strength()
            return # Modo manual
            
        preset_name = self.ui.comboBox_compliance.currentText()
        rules = ComplianceManager.get_preset_rules(preset_name)
        if not rules: return

        self.ui.spinBox_longitud.blockSignals(True)
        self.ui.spinBox_longitud.setValue(rules["length"])
        self.ui.checkBox_mayusculas.setChecked(rules["upper"])
        self.ui.checkBox_minusculas.setChecked(rules["lower"])
        self.ui.checkBox_numeros.setChecked(rules["nums"])
        self.ui.checkBox_simbolos.setChecked(rules["syms"])
        self.ui.spinBox_min_numeros.setValue(rules["min_n"])
        self.ui.spinBox_min_especiales.setValue(rules["min_s"])
        self.ui.spinBox_longitud.blockSignals(False)
        
        for ctrl in controls:
            ctrl.setEnabled(False)
            
        self.ui.label_compliance_badge.setText(f"Bloqueado por Política: {preset_name}")
        self.ui.label_compliance_badge.setVisible(True)
        self.update_password_strength()

    @Slot()
    def enable_manual_mode(self) -> None:
        self.ui.comboBox_compliance.setCurrentIndex(0)

    @Slot()
    def check_hibp(self) -> None:
        pwd = self.ui.lineEdit_validar_pass.text()
        if not pwd:
            QMessageBox.warning(self, "Vacío", "Ingresa una contraseña para validar.")
            return

        self.ui.btn_hibp_check.setEnabled(False)
        self.ui.progressBar_hibp.setVisible(True)
        self.ui.progressBar_hibp.setMaximum(0)
        self.ui.label_hibp_resultado.setText("Consultando de forma anónima...")
        self.ui.label_hibp_resultado.setStyleSheet("color: #fff;")
        self.ui.label_hibp_resultado.setVisible(True)

        worker = HIBPWorker(pwd)
        worker.signals.finished.connect(self.on_hibp_result)
        self.threadpool.start(worker)

    @Slot(int, str)
    def on_hibp_result(self, count: int, error_msg: str) -> None:
        self.ui.progressBar_hibp.setVisible(False)
        self.ui.btn_hibp_check.setEnabled(True)

        if count == -1:
            self.ui.label_hibp_resultado.setText(f"⚠️ Error: {error_msg}")
            self.ui.label_hibp_resultado.setStyleSheet("background-color: #333; color: #ffc107;")
        elif count == 0:
            self.ui.label_hibp_resultado.setText("✅ Excelente. Esta contraseña no aparece en brechas de datos conocidas.")
            self.ui.label_hibp_resultado.setStyleSheet("background-color: #198754; color: #fff;")
        else:
            self.ui.label_hibp_resultado.setText(f"🚨 PELIGRO: Esta contraseña ha sido expuesta {count:,} veces.")
            self.ui.label_hibp_resultado.setStyleSheet("background-color: #dc3545; color: #fff;")

    @Slot()
    def export_vault_ui(self) -> None:
        data = self.ui.textEdit_export_data.toPlainText()
        if not data:
            QMessageBox.warning(self, "Error", "No hay datos para exportar.")
            return

        pwd, ok = QInputDialog.getText(self, "Cifrar Bóveda", "Ingresa la contraseña maestra:", QLineEdit.Password)
        if not ok or not pwd: return

        use_argon2 = (self.ui.comboBox_vault_kdf.currentIndex() == 0) and HAS_ARGON2
        try:
            enc_data = self.vault_exporter.export_vault(data, pwd, use_argon2)
            save_path, _ = QFileDialog.getSaveFileName(self, "Guardar Bóveda", "", "CipherPass Vault (*.cpv);;JSON Files (*.json)")
            if save_path:
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(enc_data)
                self.ui.label_vault_estado.setText("✅ Bóveda exportada exitosamente.")
                self.ui.label_vault_estado.setStyleSheet("color: #2ecc71;")
        except Exception as e:
            QMessageBox.critical(self, "Error Crítico", f"Fallo al exportar: {e}")

    @Slot()
    def browse_vault_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Abrir Bóveda", "", "CipherPass Vault (*.cpv *.json);;All Files (*)")
        if file_path: self.ui.lineEdit_import_path.setText(file_path)

    @Slot()
    def import_vault_ui(self) -> None:
        path = self.ui.lineEdit_import_path.text()
        if not os.path.exists(path):
            QMessageBox.warning(self, "Error", "Archivo no encontrado.")
            return

        pwd, ok = QInputDialog.getText(self, "Descifrar Bóveda", "Ingresa la contraseña maestra:", QLineEdit.Password)
        if not ok or not pwd: return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                enc_data = f.read()
            decrypted = self.vault_exporter.import_vault(enc_data, pwd)
            if decrypted:
                self.ui.textEdit_import_data.setPlainText(decrypted)
                self.ui.label_vault_estado.setText("✅ Bóveda descifrada exitosamente.")
                self.ui.label_vault_estado.setStyleSheet("color: #2ecc71;")
            else:
                QMessageBox.critical(self, "Acceso Denegado", "Contraseña maestra incorrecta o archivo dañado.")
                self.ui.label_vault_estado.setText("❌ Fallo de descifrado.")
                self.ui.label_vault_estado.setStyleSheet("color: #e74c3c;")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Fallo de E/S: {e}")

    @Slot()
    def generate_totp_ui(self) -> None:
        name = self.ui.lineEdit_service_name.text().strip() or "ServicioDesconocido"
        secret = TOTPEngine.generate_secret()
        uri = TOTPEngine.build_uri(secret, name)

        self.ui.lineEdit_totp_secret.setText(secret)
        self.ui.lineEdit_totp_uri.setText(uri)

        if HAS_QRCODE:
            pixmap = QRHelper.generate_pixmap(uri)
            if pixmap:
                self.ui.label_qr_image.setPixmap(pixmap)
                self.ui.btn_save_qr.setEnabled(True)
        else:
            self.ui.label_qr_image.setText("Módulo 'qrcode' no instalado.\nUsa el secreto manual.")
            self.ui.btn_save_qr.setEnabled(False)

    @Slot()
    def save_qr_ui(self) -> None:
        pixmap = self.ui.label_qr_image.pixmap()
        if pixmap and not pixmap.isNull():
            save_path, _ = QFileDialog.getSaveFileName(self, "Guardar Código QR", "totp_qr.png", "Images (*.png)")
            if save_path:
                pixmap.save(save_path, "PNG")
                QMessageBox.information(self, "Éxito", "Código QR guardado correctamente.")
        else:
            QMessageBox.warning(self, "Error", "No hay un código QR para guardar.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CipherPassApp()
    sys.exit(app.exec())