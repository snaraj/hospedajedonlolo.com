# Smaller copies of the photographs

The page shows every photograph at a fraction of its delivered size, so since
release 0.1.7 (issue #16) it loads fifteen smaller copies instead, made from
the delivered files and pinned in `site/media.go` beside them like any other
media. The lightbox still opens the delivered photograph. Nothing about how
the page looks changes: each copy carries at least twice the pixels it is
drawn at, and the browser keeps the same `object-fit` crops.

## What each copy is for

| Copies | Width | Why that width |
| --- | --- | --- |
| `<tile>-806.webp` for the six rooms and the six gallery tiles | 806 px | The largest tile measured at 390, 820 and 1440 px viewports is 402.8 CSS px wide (a gallery tile at 1440; the room tiles reach 396.1). Twice that, rounded up, is 806. |
| `hero-1280.webp`, `hero-1600.webp` | 1280, 1600 px | The hero covers a box at most 850 px tall, so at the photograph's 2000×1333 shape it needs at most 1275.3 CSS px of image wherever the viewport is narrower than that, and the viewport's width elsewhere. `sizes="(max-width: 1276px) 1276px, 100vw"` states exactly that upper bound, so a browser at 1x picks the 1280 or 1600 copy and any screen at 2x or more still picks the delivered 2000 px original, as before. |
| `aerial-1440.webp`, the film's poster | 1440 px | The poster is drawn inside a 16:9 frame at most 960×540 CSS px, so the 4:3 photograph shows at most 720×540; twice that is 1440×1080. |

The rendered sizes come from a local run of the page in Chromium, Firefox and
WebKit, which agreed to the tenth of a pixel.

## How they were made

ImageMagick 7.1.2-35 (Q16-HDRI) with libwebp 1.6.0, from the delivered files
in one directory (`<source-dir>`, the same directory `scripts/stage-media.sh`
reads), writing the copies beside them:

```sh
derive() {
  magick "<source-dir>/$1.webp" -resize "$2x" -strip -quality 85 \
    -define webp:method=6 -define webp:use-sharp-yuv=true \
    "<source-dir>/$1-$2.webp"
}
for tile in family1 family2 family3 family4 queen1 queen2 \
            aerial terrace rockers garden house kitchen; do
  derive "${tile}" 806
done
derive hero 1280
derive hero 1600
derive aerial 1440
```

`-resize <width>x` keeps each photograph's own shape, so portrait originals
give 806×1075 copies. Quality 85 keeps the copies visually identical to the
delivered photographs where the page draws them: compared at the 1x tile size
after both are reduced the same way, five sampled tiles measure 39 to 43 dB
PSNR. The twelve tile copies weigh 1,548,546 bytes against the originals'
6,277,064, about a quarter. The encoder is deterministic: running the commands
above again gives files byte-identical to the pins. The
pins in `site/media.go` are the authority either way: `scripts/stage-media.sh`
refuses any file whose size or SHA-256 differs, and the server refuses to
start without every pinned file.

## Staging

With the fifteen delivered files and the fifteen copies in `<source-dir>`:

```sh
scripts/stage-media.sh <source-dir> <volume-root>
```

The copies must be on the media volume before a release that pins them is
promoted; until then the server refuses to start rather than serve a page
with missing images.
