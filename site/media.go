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

// Media is the complete, closed set of photographs and films the page uses.
// The first fifteen rows are the files exactly as exported on 2026-10-31
// (source commit c39ac49d). The rest are smaller copies made from them for
// release 0.1.7 (issue #16), named <photograph>-<width>.webp: the room and
// gallery tiles at twice their largest rendered width, the hero at 1280 and
// 1600 pixels for its srcset, and the film's poster. docs/media-derivatives.md
// records how each was made; the lightbox still opens the exported file.
// Changing a photograph is a reviewed change to this table plus a new file on
// the volume; nothing else can change what visitors see.
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
	{Name: "aerial-1440.webp", SHA256: "3b44020523f81aedac39337ec5f1b4be8e47eea5957151ed40c0cc0e454159b9", Size: 404312, ContentType: "image/webp"},
	{Name: "aerial-806.webp", SHA256: "8508ff57b435f5054b57a7aa5829565cd5c3c17bafaf8a5ca130d8d8ff6f336a", Size: 137392, ContentType: "image/webp"},
	{Name: "family1-806.webp", SHA256: "559db1c70529ab2112e20de7ab2c0e3223f6e2c330163936479f445e8b071e97", Size: 99676, ContentType: "image/webp"},
	{Name: "family2-806.webp", SHA256: "248b85e0493a8818776f1b105be51c8983f30f1792ad0cfe9e787359a56a511a", Size: 83744, ContentType: "image/webp"},
	{Name: "family3-806.webp", SHA256: "ae12d893b8de07beabe8d288def4e3ff68cc233bed6e8de753c4c35c7d459ba3", Size: 82352, ContentType: "image/webp"},
	{Name: "family4-806.webp", SHA256: "8555f0a67a3ff55d71ca72eba97214d19dfa1441c50cde05704dbc9ae98a337a", Size: 152288, ContentType: "image/webp"},
	{Name: "garden-806.webp", SHA256: "a18135a80b010660e8134f54eca0559e78977f1bca137f3079f004ecac9b4ca7", Size: 140936, ContentType: "image/webp"},
	{Name: "hero-1280.webp", SHA256: "b0ba545cb5fd7f77d77d2033c474bec0451234e641c5a216a9956ff88033b963", Size: 251468, ContentType: "image/webp"},
	{Name: "hero-1600.webp", SHA256: "4754a6130d0a1144f875d0e8e3650d12c75180ee8f60c9122d97835abf8ca6e1", Size: 349412, ContentType: "image/webp"},
	{Name: "house-806.webp", SHA256: "46925a0c5295c6bea88c61e136372c8b0d467bdda2bb844c953b1907cd4e2c90", Size: 101288, ContentType: "image/webp"},
	{Name: "kitchen-806.webp", SHA256: "8545c509ee3fb105ac8aad2e694b64d6813fc9a65409d3eeaac9c48a9a85b0a4", Size: 119676, ContentType: "image/webp"},
	{Name: "queen1-806.webp", SHA256: "513cef48f54ff6aebbac9af82d2acb56483bc7bb61f08994d2742c53453a6587", Size: 120658, ContentType: "image/webp"},
	{Name: "queen2-806.webp", SHA256: "287c13a57ebe788af42975a54579f1163588530ba0496c6d140e631f7ac52d27", Size: 135556, ContentType: "image/webp"},
	{Name: "rockers-806.webp", SHA256: "2ce087aea9ce386ad5a9a9c0e2bb983a6db06bdb5c427ec0b349da466995db22", Size: 207932, ContentType: "image/webp"},
	{Name: "terrace-806.webp", SHA256: "494f1196d4155992d7b4a832818df0270889fe09ad84c8cc2764a080ebf525a4", Size: 167048, ContentType: "image/webp"},
}
