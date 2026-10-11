# Stage 4 hints (add in CTFd; costs follow the 0 / 10% / 20% rule of the 300-point value, Kosgollage sets the final numbers)

| # | Cost | Hint |
|---|------|------|
| 1 | 0 pts  | Nothing was deleted or wiped. NTFS lets a file carry extra data that normal file listings and file sizes do not show. |
| 2 | 30 pts | Open the image in Autopsy (Add Data Source -> Disk Image) or FTK Imager and browse Users > subjectc > Documents. One of the files has more than one data stream. |
| 3 | 60 pts | Extract the second stream of Resume.txt. It is a zip archive. Its password is your answer from the previous case file, exactly as submitted. The recovery note inside holds this stage's reference code. |
