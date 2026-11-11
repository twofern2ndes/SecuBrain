; SecuBrain Windows installer (Inno Setup 6.x).
; This package contains ONLY SecuBrain's original program and documentation.
; Nmap and Npcap are NOT distributed by this setup. Users install them independently.

#define AppName "SecuBrain"
#define AppVersion "0.4.0"
#define AppPublisher "twofern2ndes"

[Setup]
AppId={{A773E868-5B0E-4F7F-B459-2CF52112F663}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName=SecuBrain {#AppVersion} (prototype)
AppPublisher={#AppPublisher}
AppPublisherURL=https://github.com/twofern2ndes/SecuBrain
AppSupportURL=https://github.com/twofern2ndes/SecuBrain/issues
AppUpdatesURL=https://github.com/twofern2ndes/SecuBrain/releases
DefaultDirName={localappdata}\Programs\SecuBrain
DefaultGroupName=SecuBrain
AllowNoIcons=yes
PrivilegesRequired=lowest
WizardStyle=modern
WizardImageFile=assets\wizard.bmp
WizardSmallImageFile=assets\wizard-small.bmp
SetupIconFile=assets\secubrain.ico
UninstallDisplayIcon={app}\secubrain.ico
LicenseFile=..\legal\INSTALLER-TERMS.txt
InfoBeforeFile=..\legal\INSTALL-NOTES.txt
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=SecuBrain-Setup-v{#AppVersion}-windows-x64
Compression=lzma2
SolidCompression=yes
ChangesEnvironment=yes
MinVersion=10.0
DisableWelcomePage=no
DisableDirPage=no
DisableReadyPage=no
DisableFinishedPage=no
VersionInfoVersion=0.4.0.0
VersionInfoDescription=SecuBrain local-first security auditing CLI
VersionInfoCompany={#AppPublisher}
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "userpath"; Description: "Add SecuBrain to my user PATH (recommended for PowerShell / Command Prompt)"; GroupDescription: "Terminal integration:"; Flags: checkedonce

[Files]
Source: "..\dist\secubrain.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\secubrain.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\legal\INSTALLER-TERMS.txt"; DestDir: "{app}\legal"; Flags: ignoreversion
Source: "..\legal\INSTALL-NOTES.txt"; DestDir: "{app}\legal"; Flags: ignoreversion
Source: "..\docs\*.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\SecuBrain CLI"; Filename: "{app}\secubrain.exe"; WorkingDir: "{userdocs}"; IconFilename: "{app}\secubrain.ico"; Comment: "Open the SecuBrain interactive security auditor"
Name: "{group}\SecuBrain Documentation"; Filename: "{app}\README.md"
Name: "{group}\Uninstall SecuBrain"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SecuBrain CLI"; Filename: "{app}\secubrain.exe"; WorkingDir: "{userdocs}"; IconFilename: "{app}\secubrain.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\secubrain.exe"; Description: "Launch SecuBrain CLI"; Flags: postinstall nowait skipifsilent unchecked
Filename: "https://nmap.org/download.html"; Description: "Open the official Nmap download page (optional separate installation)"; Flags: shellexec postinstall skipifsilent unchecked

[Code]
var
  NmapPage: TWizardPage;
  NmapText: TNewStaticText;
  NmapButton: TNewButton;

function UserExecutableDir(): String;
begin
  Result := ExpandConstant('{app}');
end;

function ContainsPathEntry(const AllPaths, Entry: String): Boolean;
begin
  Result := Pos(';' + Uppercase(Entry) + ';', ';' + Uppercase(AllPaths) + ';') <> 0;
end;

procedure UpdateUserPath(const AddEntry: Boolean);
var
  PathText, Target, NewText: String;
  Managed: Cardinal;
begin
  Target := UserExecutableDir();
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', PathText) then
    PathText := '';
  if AddEntry then
  begin
    if not ContainsPathEntry(PathText, Target) then
    begin
      if PathText = '' then
        NewText := Target
      else if Copy(PathText, Length(PathText), 1) = ';' then
        NewText := PathText + Target
      else
        NewText := PathText + ';' + Target;
      if RegWriteExpandStringValue(HKCU, 'Environment', 'Path', NewText) then
        RegWriteDWordValue(HKCU, 'Software\SecuBrain', 'PathManaged', 1);
    end;
  end
  else
  begin
    { Never delete a PATH entry which this installer did not create. }
    if not RegQueryDWordValue(HKCU, 'Software\SecuBrain', 'PathManaged', Managed) then Exit;
    if Managed <> 1 then Exit;
    NewText := ';' + PathText + ';';
    StringChangeEx(NewText, ';' + Target + ';', ';', True);
    if NewText = ';' then
      NewText := ''
    else if Length(NewText) >= 2 then
      NewText := Copy(NewText, 2, Length(NewText) - 2);
    if NewText <> PathText then
      RegWriteExpandStringValue(HKCU, 'Environment', 'Path', NewText);
    RegDeleteValue(HKCU, 'Software\SecuBrain', 'PathManaged');
  end;
end;

procedure OpenNmapOfficialSite(Sender: TObject);
var
  ResultCode: Integer;
begin
  if not ShellExec('open', 'https://nmap.org/download.html', '', '', SW_SHOWNORMAL, ewNoWait, ResultCode) then
    MsgBox('Please open https://nmap.org/download.html in your browser.', mbInformation, MB_OK);
end;

function NmapInstallStatus(): String;
begin
  if FileExists(ExpandConstant('{pf64}\Nmap\nmap.exe')) or
     FileExists(ExpandConstant('{pf32}\Nmap\nmap.exe')) or
     FileExists(ExpandConstant('{localappdata}\Nmap\nmap.exe')) then
    Result := 'Detected in a common install location; confirm with secubrain doctor.'
  else
    Result := 'Not found in the common locations; you can install it separately.';
end;

procedure InitializeWizard;
begin
  NmapPage := CreateCustomPage(wpSelectTasks, 'Nmap integration (optional)',
    'Install Nmap separately from the official project.');
  NmapText := TNewStaticText.Create(NmapPage);
  NmapText.Parent := NmapPage.Surface;
  NmapText.AutoSize := False;
  NmapText.WordWrap := True;
  NmapText.SetBounds(0, ScaleY(12), NmapPage.SurfaceWidth, ScaleY(176));
  NmapText.Caption :=
    'SecuBrain v0.3 offers quick, standard, full TCP, and optional UDP/OS/NSE scanning through Nmap.' + #13#10#13#10 +
    'Nmap installation: ' + NmapInstallStatus() + #13#10#13#10 +
    'Nmap and Npcap are separate projects with independent licenses. Redistributing their free Windows installers within SecuBrain is not permitted without appropriate rights.' + #13#10#13#10 +
    'To enable Nmap checks: install SecuBrain, download Nmap independently from the official website, complete the Nmap/Npcap installer and license prompts, then run: secubrain doctor.' + #13#10#13#10 +
    'Normal local source audits work even if you do not install Nmap.';
  NmapButton := TNewButton.Create(NmapPage);
  NmapButton.Parent := NmapPage.Surface;
  NmapButton.SetBounds(0, ScaleY(196), ScaleX(248), ScaleY(30));
  NmapButton.Caption := 'Open official Nmap download page';
  NmapButton.OnClick := @OpenNmapOfficialSite;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('userpath') then
    UpdateUserPath(True);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    UpdateUserPath(False);
end;
