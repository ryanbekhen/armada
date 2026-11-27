//! A tab writer with the settings Armada's tables use (padding
//! with spaces, left-aligned, no flags): cells end at a tab, a column's
//! width is its widest cell in runes plus the padding, and a line without
//! a tab ends the block of lines whose columns line up.

#[derive(Clone, Copy, Default)]
struct Cell {
    size: usize,
    width: usize,
}

/// A tabwriter.Writer writing into a String.
pub struct TabWriter {
    minwidth: usize,
    padding: usize,
    out: String,
    buf: String,
    pos: usize,
    cell: Cell,
    lines: Vec<Vec<Cell>>,
    widths: Vec<usize>,
}

impl TabWriter {
    /// tabwriter.NewWriter(out, minwidth, tabwidth, padding, ' ', 0); the
    /// tab width only matters for tab padding, which Armada never uses.
    pub fn new(minwidth: usize, padding: usize) -> TabWriter {
        let mut w = TabWriter {
            minwidth,
            padding,
            out: String::new(),
            buf: String::new(),
            pos: 0,
            cell: Cell::default(),
            lines: Vec::new(),
            widths: Vec::new(),
        };
        w.reset();
        w
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.pos = 0;
        self.cell = Cell::default();
        self.lines.clear();
        self.widths.clear();
        self.lines.push(Vec::new());
    }

    fn update_width(&mut self) {
        self.cell.width += self.buf[self.pos..].chars().count();
        self.pos = self.buf.len();
    }

    fn terminate_cell(&mut self) -> usize {
        let line = self.lines.last_mut().expect("a line");
        line.push(self.cell);
        self.cell = Cell::default();
        line.len()
    }

    /// Write, as tabwriter.Writer.Write.
    pub fn write(&mut self, s: &str) {
        let mut n = 0;
        for (i, ch) in s.char_indices() {
            if matches!(ch, '\t' | '\x0b' | '\n' | '\x0c') {
                self.buf.push_str(&s[n..i]);
                self.cell.size += i - n;
                self.update_width();
                n = i + 1;
                let ncells = self.terminate_cell();
                if ch == '\n' || ch == '\x0c' {
                    self.lines.push(Vec::new());
                    if ch == '\x0c' || ncells == 1 {
                        self.flush_no_defers();
                    }
                }
            }
        }
        self.buf.push_str(&s[n..]);
        self.cell.size += s.len() - n;
    }

    fn write_padding(&mut self, textw: usize, cellw: usize) {
        self.out.push_str(&" ".repeat(cellw.saturating_sub(textw)));
    }

    fn write_lines(&mut self, pos0: usize, line0: usize, line1: usize) -> usize {
        let mut pos = pos0;
        for i in line0..line1 {
            let line = self.lines[i].clone();
            for (j, c) in line.iter().enumerate() {
                if c.size == 0 {
                    if j < self.widths.len() {
                        let w = self.widths[j];
                        self.write_padding(c.width, w);
                    }
                } else {
                    let text = self.buf[pos..pos + c.size].to_string();
                    self.out.push_str(&text);
                    pos += c.size;
                    if j < self.widths.len() {
                        let w = self.widths[j];
                        self.write_padding(c.width, w);
                    }
                }
            }
            if i + 1 == self.lines.len() {
                let text = self.buf[pos..pos + self.cell.size].to_string();
                self.out.push_str(&text);
                pos += self.cell.size;
            } else {
                self.out.push('\n');
            }
        }
        pos
    }

    fn format(&mut self, pos0: usize, mut line0: usize, line1: usize) -> usize {
        let mut pos = pos0;
        let column = self.widths.len();
        let mut this = line0;
        while this < line1 {
            if column + 1 >= self.lines[this].len() {
                this += 1;
                continue;
            }
            pos = self.write_lines(pos, line0, this);
            line0 = this;
            let mut width = self.minwidth;
            while this < line1 {
                let line = &self.lines[this];
                if column + 1 >= line.len() {
                    break;
                }
                width = width.max(line[column].width + self.padding);
                this += 1;
            }
            self.widths.push(width);
            pos = self.format(pos, line0, this);
            self.widths.pop();
            line0 = this;
        }
        self.write_lines(pos, line0, line1)
    }

    fn flush_no_defers(&mut self) {
        if self.cell.size > 0 {
            self.terminate_cell();
        }
        let n = self.lines.len();
        self.format(0, 0, n);
        self.reset();
    }

    /// Flush and return everything written.
    pub fn finish(mut self) -> String {
        self.flush_no_defers();
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns() {
        let mut w = TabWriter::new(0, 2);
        w.write("NAME\tREADY\tIMAGE\n");
        w.write("web\t1/1\tnginx\n");
        w.write("a-long-name\t10/10\tx\n");
        assert_eq!(
            w.finish(),
            "NAME         READY  IMAGE\nweb          1/1    nginx\na-long-name  10/10  x\n"
        );
    }

    #[test]
    fn a_line_without_tabs_ends_the_block() {
        let mut w = TabWriter::new(0, 2);
        w.write("Name:\tweb\nRevision:\tweb--r1\n\nREPLICA\tNODE\nweb-r1-abcde\tn1\n");
        assert_eq!(
            w.finish(),
            "Name:      web\nRevision:  web--r1\n\nREPLICA       NODE\nweb-r1-abcde  n1\n"
        );
    }

    #[test]
    fn runes() {
        let mut w = TabWriter::new(0, 2);
        w.write("r1 → r2\tx\nab\ty\n");
        assert_eq!(w.finish(), "r1 → r2  x\nab       y\n");
    }
}
