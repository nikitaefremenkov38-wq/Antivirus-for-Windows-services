#define MyAppName "Tray App Antivirus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "akula5561"
#define MyAppExeName "tray-app.exe"
#define MyServiceExeName "tray-service.exe"
#define MyControlExeName "tray-control.exe"
#define MyServiceName "TrayAppService"
#define MyServiceDisplayName "Tray App Service"

#ifndef MyBuildDir
  #define MyBuildDir "..\build\Release"
#endif

[Setup]
AppId={{0F69E657-9B34-4AD1-B43C-7D8E580B0B31}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Tray App Antivirus
DefaultGroupName=Tray App Antivirus
DisableProgramGroupPage=yes
OutputDir={#MyBuildDir}
OutputBaseFilename=tray-antivirus-setup
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern

[Files]
Source: "{#MyBuildDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyBuildDir}\{#MyServiceExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyBuildDir}\{#MyControlExeName}"; DestDir: "{app}"; Flags: ignoreversion

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function ExecAndWait(const FileName: string; const Params: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function ExecIgnoringExitCode(const FileName: string; const Params: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure InstallOrUpdateService;
var
  ServiceExe: string;
begin
  ServiceExe := ExpandConstant('{app}\{#MyServiceExeName}');
  ExecIgnoringExitCode(ExpandConstant('{sys}\sc.exe'),
    'create "' + '{#MyServiceName}' + '" binPath= """' + ServiceExe + '""" start= auto DisplayName= """' + '{#MyServiceDisplayName}' + '"""');
  ExecIgnoringExitCode(ExpandConstant('{sys}\sc.exe'),
    'config "' + '{#MyServiceName}' + '" start= auto binPath= """' + ServiceExe + '""" DisplayName= """' + '{#MyServiceDisplayName}' + '"""');
  ExecIgnoringExitCode(ExpandConstant('{sys}\sc.exe'), 'start "' + '{#MyServiceName}' + '"');
end;

procedure StopAndDeleteService;
begin
  ExecIgnoringExitCode(ExpandConstant('{app}\{#MyControlExeName}'), '--stop-service');
  ExecIgnoringExitCode(ExpandConstant('{sys}\taskkill.exe'), '/IM {#MyAppExeName} /F');
  ExecIgnoringExitCode(ExpandConstant('{sys}\taskkill.exe'), '/IM {#MyServiceExeName} /F');
  ExecIgnoringExitCode(ExpandConstant('{sys}\sc.exe'), 'delete "' + '{#MyServiceName}' + '"');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    InstallOrUpdateService;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopAndDeleteService;
  end;
end;
