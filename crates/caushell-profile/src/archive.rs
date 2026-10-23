#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveInvocation {
    pub archive: String,
    pub directories: Vec<String>,
}

pub fn gnu_tar_extraction(argv: &[String]) -> Result<ArchiveInvocation, &'static str> {
    if argv.len() > 4096 || argv.iter().map(String::len).sum::<usize>() > 65_536 {
        return Err("archive option budget exceeded");
    }
    let argv = crate::option_environment::modern_tar_argv(argv)
        .ok_or("unsupported old-style archive options")?;
    let mut archive = None;
    let mut directories = Vec::new();
    let mut extracts = 0;
    let mut force_local = false;
    let mut index = 0;
    while index < argv.len() {
        let arg = &argv[index];
        if arg == "--" && index + 1 == argv.len() {
            break;
        }
        let mut operand = |attached: &str| -> Result<String, &'static str> {
            if !attached.is_empty() {
                return Ok(attached.into());
            }
            index += 1;
            argv.get(index)
                .cloned()
                .ok_or("archive option has no operand")
        };
        if let Some(long) = arg.strip_prefix("--") {
            let (flag, attached) = long
                .split_once('=')
                .map(|(flag, value)| (flag, Some(value)))
                .unwrap_or((long, None));
            match (flag, attached) {
                ("extract" | "get", None) => extracts += 1,
                ("verbose", None) => {}
                ("force-local", None) => force_local = true,
                ("file", _) => {
                    let value = match attached {
                        Some(value) => value.into(),
                        None => operand("")?,
                    };
                    if archive.replace(value).is_some() {
                        return Err("multiple archives are unsupported");
                    }
                }
                ("directory", _) => directories.push(match attached {
                    Some(value) => value.into(),
                    None => operand("")?,
                }),
                _ => return Err("unsupported archive extraction option or transform"),
            }
        } else if let Some(short) = arg.strip_prefix('-').filter(|s| !s.is_empty()) {
            for (offset, letter) in short.char_indices() {
                match letter {
                    'x' => extracts += 1,
                    'v' => {}
                    'f' | 'C' => {
                        let value = operand(&short[offset + 1..])?;
                        if letter == 'f' {
                            if archive.replace(value).is_some() {
                                return Err("multiple archives are unsupported");
                            }
                        } else {
                            directories.push(value);
                        }
                        break;
                    }
                    _ => return Err("unsupported archive extraction option or transform"),
                }
            }
        } else {
            return Err("archive member selection is unsupported");
        }
        index += 1;
    }
    let archive = archive.ok_or("archive input is not explicit")?;
    if extracts != 1
        || archive.is_empty()
        || archive == "-"
        || (!force_local && archive.contains(':'))
        || archive.contains('\0')
        || directories.iter().any(|p| p.is_empty() || p.contains('\0'))
    {
        return Err("archive source or operation is not a local file extraction");
    }
    Ok(ArchiveInvocation {
        archive,
        directories,
    })
}
