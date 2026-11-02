# Attribution: English word list (`vocab-en.ts`)

`vocab-en.ts` (and the statistics derived from it in `state-table.ts`) is an adapted
work of the **FrequencyWords** English frequency list.

- **Work**: FrequencyWords, file `content/2018/en/en_50k.txt`
- **Author**: Hermit Dave (GitHub: `hermitdave`)
- **Source URL**: https://github.com/hermitdave/FrequencyWords
- **Upstream corpus**: OpenSubtitles 2018 via OPUS (http://opus.nlpl.eu/OpenSubtitles2018.php)
- **License of the word-list content**: Creative Commons Attribution-ShareAlike 4.0
  International (CC BY-SA 4.0), https://creativecommons.org/licenses/by-sa/4.0/
  The full license text is in `vocab-en.LICENSE.txt` next to this file.
  (The FrequencyWords *code* is MIT; no FrequencyWords code is used here, only data.)

## Modifications made (CC BY-SA 4.0 section 3(a)(1)(B))
1. Kept only tokens matching `[a-z]+` (dropped digits, punctuation, apostrophes, non-ASCII).
2. Removed duplicates, keeping the first (highest-count) occurrence.
3. Kept the top 32,768 tokens by occurrence count, with their counts.
4. Packed the words and counts into a TypeScript module (`vocab-en.ts`).
5. At run time the words are re-ordered within near-equal-frequency rank groups by a
   per-session key; the counts are used as an rANS frequency table.
6. `state-table.ts` holds simulation statistics computed from these counts.

## ShareAlike
This adapted word list is licensed under **CC BY-SA 4.0**, the same license. ShareAlike
applies to the adapted word-list data (`vocab-en.ts`, `state-table.ts`) and to any
further adaptation of it. It does not by itself relicense the rest of this repository.
Because the list is bundled into `public/agent/lexis-frame.mjs`, a copy of this notice
ships as `public/agent/NOTICE-vocab.txt`.

No endorsement by the author or by Creative Commons is implied. Provided "as is",
without warranties (see license section 5).
