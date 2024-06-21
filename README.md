# SlimDetours

SlimDetours is a Windows API hooking library based on [Microsoft Detours](https://github.com/microsoft/Detours), currently is supported and developed by [KNSoft](https://github.com/KNSoft).

Compared to original [Detours](https://github.com/microsoft/Detours), SlimDetours aim at:

- Lite
  - Depends on `Ntdll.dll` only (powered by [Wintexports](https://github.com/KNSoft/Wintexports))
  - Preserve API hooking functions only
  - Drop support for ARM (ARM32), IA64, GNUC, WinXP
- Stable
  - Automatically update threads when commit detours
  - Use strict boundary check to verify PE instead of SEH (`try-except` statement)
  - Code fixes and improvements
- Out-of-the-box
  - NuGet package releases
  - Static library releases compatible with different versions of MSVC compiler

## License

SlimDetours is based on [Microsoft Detours](https://github.com/microsoft/Detours) which is licensed under the [MIT](https://github.com/microsoft/Detours/blob/main/LICENSE) license.

SlimDetours is licensed under the [MPL-2.0](LICENSE.md) license.

SlimDetours also uses [KNSoft/NDK](https://github.com/KNSoft/KNSoft.NDK) to access low-level Windows NT APIs.
