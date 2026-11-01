package site

// Object is one media file the page references by `assets/<Name>`.
//
// The digest is the identity: on the volume the file lives at
// `immutable/<SHA256>/<Name>`, the same content-addressed layout
// naranjo.online uses for its gallery, and the server verifies every byte
// against SHA256 before it reports ready.
type Object struct {
	Name        string
	SHA256      string
	Size        int64
	ContentType string
}

// Media is the complete, closed set of photographs and films the page uses,
// exactly as exported on 2026-10-31 (source commit c39ac49d). Changing a
// photograph is a reviewed change to this table plus a new file on the volume;
// nothing else can change what visitors see.
var Media = []Object{
	{Name: "aerial.webp", SHA256: "baf5f72da9dfbe7acf689da40ec4a0bbdfd5cd9411fd43b07586c55a6d7c5e29", Size: 763632, ContentType: "image/webp"},
	{Name: "don-lolo.mp4", SHA256: "084fa3c51ef60288b71477d889701e13a80406bda4a0464ebb10408afe688ebf", Size: 19997437, ContentType: "video/mp4"},
	{Name: "family1.webp", SHA256: "addb884b4cfcd5e422283cade5a861086eafd6d0c64e97354ce41ad5b4e808cc", Size: 598838, ContentType: "image/webp"},
	{Name: "family2.webp", SHA256: "7e51167996c7bdd278357e475c806f83e2bd2fb26d9e888cb67fa07a9e624c7e", Size: 434968, ContentType: "image/webp"},
	{Name: "family3.webp", SHA256: "7d24c5107d6801d182645d92c4727886c75352c025fae4117dede11347a04aa1", Size: 484382, ContentType: "image/webp"},
	{Name: "family4.webp", SHA256: "28f69aac6dbbb236156721834738b7954ebd40f2a82214f5a3c6056505327352", Size: 335546, ContentType: "image/webp"},
	{Name: "garden.webp", SHA256: "f4a7c339ae0046f00811712b2d12df28b11f357a830923d4faf23bf7418c0ab7", Size: 723694, ContentType: "image/webp"},
	{Name: "hero.webp", SHA256: "49ceaada61c05713d59489600de01f48627187227b995ccfbdf9b0610c48a501", Size: 499682, ContentType: "image/webp"},
	{Name: "house.webp", SHA256: "8ae4dfff5500a9d47709f6abd3e1cd05d1ccfeae99bff2272cfd504ba19b40fa", Size: 456284, ContentType: "image/webp"},
	{Name: "kitchen.webp", SHA256: "7e577ac964fbd3084627ee3f9f2e4575c2c7e4cc823cffd1b29ca299ce4b9f50", Size: 291592, ContentType: "image/webp"},
	{Name: "peacock.webp", SHA256: "55f6f7201947cb3533aea0d2836d38b6ffdee508a63fd889aba1f3150b9fece6", Size: 363254, ContentType: "image/webp"},
	{Name: "queen1.webp", SHA256: "78eaaa481f8dffb7638fc5d322e9046f5ecbf847adfa8a1836a9b974aa9dff29", Size: 696532, ContentType: "image/webp"},
	{Name: "queen2.webp", SHA256: "91b5205f7b779d88092ef35766e3afbf615e6545067dc2cfc771747ed61006b8", Size: 700060, ContentType: "image/webp"},
	{Name: "rockers.webp", SHA256: "b1feac61eef9088601675371bc4d2b5afbdda3490bdb107c01e58e8b387c0be4", Size: 437452, ContentType: "image/webp"},
	{Name: "terrace.webp", SHA256: "f1786cb095adaf1592351a70fadaff18bad4b7dd2d0c8cbb3cc2fd382b54302d", Size: 354084, ContentType: "image/webp"},
}

// Withheld names pinned media that stays on the volume and is verified at
// startup, but is not delivered. The film is withheld under the platform's
// zero-spend boundary for public video (snaraj/platform safety invariant 13):
// on a self-serve plan, video through the proxied edge needs a paid service,
// and only the owner can lift that boundary. The page keeps its poster image.
// Delivering the film is removing its name here, after that owner decision.
var Withheld = []string{"don-lolo.mp4"}
