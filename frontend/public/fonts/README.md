# Self-hosted fonts

Geist (UI) and Geist Mono (identifiers: IPs, ports, CVE IDs, hashes, scores, dates) are
the Constellus typefaces (planning#337, identity D). They are served from this folder so
nothing is fetched from a font CDN at runtime. The `@font-face` rules live in
`src/index.css`; `index.html` preloads both files.

| File | Bytes | Source inside the package | SHA-256 |
|---|---|---|---|
| `Geist-Variable.woff2` | 69,488 | `dist/fonts/geist-sans/Geist-Variable.woff2` | `3626eba547294501c8a4d662c7d9ea3b49734409a4c5a1ccf12fa86429b1687e` |
| `GeistMono-Variable.woff2` | 71,212 | `dist/fonts/geist-mono/GeistMono-Variable.woff2` | `5d93ee62680bbec1abc5405c2658311f9396f6f9a821ef8551ec463887e600d4` |

- **Publisher:** Vercel, the type's authors. npm package `geist` v1.9.2, published
  2026-11-06, tarball integrity
  `sha512-UU1x2q5Khob0+i4csFvXk1Ki4DePdu7xISuXyEcj1tzQMg64oN7Kbuy4e5z5QhcUWbbvOMJNs3ZxYQqpsEMV3w==`.
  Upstream repository: `vercel/geist-font`.
- **Licence:** SIL Open Font License 1.1. `LICENSE-OFL.txt` is the package's `LICENSE.txt`
  verbatim and must stay next to the font files.
- **Why vendored, not a dependency:** the `geist` package ships 8 MB of TTF plus Next.js
  glue the app never imports; the Fontsource builds are not by the authors and lag
  upstream. Two woff2 files are an asset, not a library (planning#337 comment 6788819370).
- Variable weight axis 100–900. The app uses 400 / 500 / 600, and 700 for the verdict.

## Updating

1. In an empty scratch directory outside the repo, run `npm pack geist@<version>` and
   extract the two files above from the tarball (`tar -xzf geist-<version>.tgz <paths>`).
2. Check the first four bytes of each file are `wOF2` (`head -c 4 <file>`), then record the
   new version, publish date, tarball integrity and SHA-256 values in this table.
3. Copy the files over the ones here. `npm test` runs `src/lib/fonts.test.ts`, which checks
   that both files exist, are woff2, are the ones `index.css` and `index.html` reference,
   and that no CDN URL has crept into either file.
