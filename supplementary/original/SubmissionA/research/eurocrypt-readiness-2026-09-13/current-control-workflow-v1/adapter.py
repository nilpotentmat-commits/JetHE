"""Control algorithm unchanged; explicit current arithmetic backend per instance."""
from worker import *
from fixed_binding import SlimRingBase as CurrentRingBase

class CurrentControlWorker(Worker):
    def __init__(self, mode, arm, index):
        assert arm == 'control'
        super().__init__(mode, arm, index)

    def setup(self):
        start=perf_counter()
        with timed(self.setup_times,'public_context_codec'):
            self.ring=CurrentRingBase(256,1)
            _,_,_,_,self.rows,self.inverse=codec_setup()
            self.field=SharedField()
            assert self.ring.moduli[self.terminal_limbs]==(NATIVE_Q if self.arm=='native' else Q)
            if self.arm=='control':
                self.interpolation=Interpolation(self.field)
                self.records=records(16,256)
                assert len(self.records)==175776
        with timed(self.setup_times,'keys_and_hints'):
            coins=Coins(self.ring)
            if self.arm=='native':
                self.keys,self.pks,self.banks=native.setup(self.ring,coins)
            else:
                coeff=coins.ternary('secret/root')
                secret=Secret('root',1,coeff,self.ring.lift(coeff,1))
                self.keys={'root':secret}
                self.pks={'root':keygen(self.ring,coins,secret)}
                self.banks={}
            self.secret=self.keys['h1' if self.arm=='native' else 'root']
        with timed(self.setup_times,'recipient_key_preparation'):
            self.square=self.ring.point(self.secret.spectra,self.secret.spectra,self.terminal_limbs)
        with timed(self.setup_times,'public_material_serialization'):
            rec=[(name+'/'+str(j),row) for name,bank in self.banks.items() for j,row in enumerate(bank.rows)]
            rec.extend((name,pk.components) for name,pk in self.pks.items())
            self.public_wire=serialize('public',rec)
        self.material=dict(independent_secrets=len(self.keys),public_keys=len(self.pks),
            evaluation_rows=sum(len(b.rows) for b in self.banks.values()),
            setup_error_vectors=coins.errors,setup_small_vectors=len(self.keys)+coins.errors,
            public_material_raw_bytes=self.public_wire['raw_bytes'],
            public_material_serialized_bytes=self.public_wire['wire_bytes'],
            constructed_linear_buffers_bytes=16384+(len(self.ring.public_t)*8 if self.arm=='native' else
                sum(len(a)*a.itemsize for a in (self.interpolation.inverse_flat,self.interpolation.evaluation_flat,self.interpolation.logs,self.interpolation.exps))))
        assert self.material['public_material_raw_bytes']==(391 if self.arm=='native' else 1)<<20
        assert coins.errors==(139 if self.arm=='native' else 1)
        self.setup_wall=perf_counter()-start
        del coins,rec
        emit('setup_complete',arm=self.arm,index=self.index,setup_wall_seconds=self.setup_wall,material=self.material)

